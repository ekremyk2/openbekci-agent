// Command openbekci-agent is the OpenBekci on-site access agent.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/openbekci/openbekci-agent/internal/agent"
	"github.com/openbekci/openbekci-agent/internal/config"
	"github.com/openbekci/openbekci-agent/internal/driver"
	"github.com/openbekci/openbekci-agent/internal/driver/mock"
	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/spf13/cobra"
)

// Set by GoReleaser (-ldflags).
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Exit codes. systemd's RestartPreventExitStatus=3 keeps a revoked agent from
// restart-looping.
const (
	exitFailure = 1
	exitRevoked = 3
)

func main() {
	if err := newRoot().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		if errors.Is(err, agent.ErrRevoked) {
			os.Exit(exitRevoked)
		}
		os.Exit(exitFailure)
	}
}

func newRoot() *cobra.Command {
	var cfgPath string
	root := &cobra.Command{
		Use:           "openbekci-agent",
		Short:         "OpenBekci on-site access agent: drives gates and doors on the site LAN, offline-capable",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "path to agent.yaml (default "+config.DefaultPath()+", env "+config.EnvPrefix+"CONFIG)")
	load := func() (*config.Config, string, error) {
		path := cfgPath
		if path == "" {
			path = config.DefaultPath()
		}
		c, err := config.Load(path)
		return c, path, err
	}
	root.AddCommand(enrolCmd(load), runCmd(load), statusCmd(load), rotateCmd(load), configCmd(load), versionCmd())
	return root
}

type loader func() (*config.Config, string, error)

func enrolCmd(load loader) *cobra.Command {
	var server, token, org, site string
	cmd := &cobra.Command{
		Use:   "enrol",
		Short: "Enrol this agent with the server using a one-time token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, path, err := load()
			if err != nil {
				return err
			}
			if server != "" {
				cfg.Server = server
			}
			if cfg.Server == "" {
				return errors.New("--server is required (or set server in agent.yaml / " + config.EnvPrefix + "SERVER)")
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
			defer stop()
			id, err := agent.Enrol(ctx, cfg, agent.EnrolOptions{Server: cfg.Server, Token: token, Org: org, Site: site, Version: version})
			if err != nil {
				return err
			}
			if err := writeInitialConfig(path, cfg); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not write %s: %v\n", path, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Enrolled as agent %s (site %s). Credential stored in %s.\nStart the service with `openbekci-agent run` (or systemctl start openbekci-agent).\n",
				id.AgentID, id.SiteID, cfg.StateDir)
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "server base URL, https://...")
	cmd.Flags().StringVar(&token, "token", "", "one-time enrolment token (obk_enr_...)")
	cmd.Flags().StringVar(&org, "org", "", "organization id (only for the org/site scoped enrolment endpoint)")
	cmd.Flags().StringVar(&site, "site", "", "site id (only for the org/site scoped enrolment endpoint)")
	_ = cmd.MarkFlagRequired("token")
	return cmd
}

// writeInitialConfig creates agent.yaml with the server URL when no file exists
// yet; an existing file is never modified.
func writeInitialConfig(path string, cfg *config.Config) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	initial := config.Config{Server: cfg.Server, StateDir: cfg.StateDir, CAFile: cfg.CAFile, LogLevel: "info", OfflineGraceHours: 72}
	raw, err := initial.Marshal()
	if err != nil {
		return err
	}
	header := []byte("# openbekci-agent configuration. Declare your hardware under `drivers:`; see deploy/agent.example.yaml.\n")
	return os.WriteFile(path, append(header, raw...), 0o640) //nolint:gosec // group-readable so the service user can read what root enrolled with
}

func newLogger(cfg *config.Config) (*slog.Logger, error) {
	lvl, err := cfg.Level()
	if err != nil {
		return nil, err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	if lvl <= slog.LevelDebug {
		log.Warn("log_level debug: plates are written to the log (personal data); use only while troubleshooting")
	}
	return log, nil
}

func runCmd(load loader) *cobra.Command {
	var (
		useMock    bool
		mockCfg    mock.Config
		mockListen string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the agent in the foreground (the service entry point)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := load()
			if err != nil {
				return err
			}
			if err := cfg.Validate(driverTypes()); err != nil {
				return err
			}
			log, err := newLogger(cfg)
			if err != nil {
				return err
			}
			if useMock {
				mockCfg.Listen = mockListen
				log.Warn("running with the mock driver: no real hardware is read or driven")
			}
			a, err := agent.New(agent.Options{Config: cfg, Registrations: Drivers, Version: version, Log: log, Mock: useMock, MockConfig: mockCfg})
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return a.Run(ctx)
		},
	}
	cmd.Flags().BoolVar(&useMock, "mock", false, "ignore configured drivers; use one scriptable mock driver for every point (demos and tests)")
	cmd.Flags().StringVar(&mockListen, "mock-listen", "127.0.0.1:8099", "with --mock: loopback address of the POST /present injection endpoint (empty disables)")
	cmd.Flags().StringVar(&mockCfg.Script, "mock-script", "", "with --mock: JSON file of scripted presentations [{after_ms, instance?, channel, kind, value}]")
	cmd.Flags().BoolVar(&mockCfg.Loop, "mock-loop", false, "with --mock: replay the script forever")
	cmd.Flags().StringVar(&mockCfg.OpenLog, "mock-open-log", "", "with --mock: file that records every open, one JSON line each")
	return cmd
}

func statusCmd(load loader) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show enrolment, allow-list version, queue depth, driver health and last server contact",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := load()
			if err != nil {
				return err
			}
			st, err := agent.ReadStatus(cmd.Context(), cfg.StateDir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"version": version, "agent_id": st.Identity.AgentID, "site_id": st.Identity.SiteID,
					"snapshot_version": st.SnapshotVersion, "config_version": st.ConfigVersion, "entries": st.Entries,
					"queue_depth": st.QueueDepth, "dropped_events": st.DroppedEvents, "last_contact": st.LastContact, "timezone": st.Timezone,
					"drivers": st.Drivers, "quarantined_since": st.QuarantinedSince,
				})
			}
			w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
			fmt.Fprintf(w, "version\t%s\n", version)
			fmt.Fprintf(w, "agent id\t%s\n", st.Identity.AgentID)
			fmt.Fprintf(w, "site id\t%s\n", st.Identity.SiteID)
			fmt.Fprintf(w, "allow-list version\t%d (%d entries)\n", st.SnapshotVersion, st.Entries)
			fmt.Fprintf(w, "config version\t%d\n", st.ConfigVersion)
			fmt.Fprintf(w, "site timezone\t%s\n", orDash(st.Timezone))
			fmt.Fprintf(w, "queue depth\t%d (dropped %d)\n", st.QueueDepth, st.DroppedEvents)
			if st.LastContact.IsZero() {
				fmt.Fprintf(w, "last contact\tnever\n")
			} else {
				fmt.Fprintf(w, "last contact\t%s (%s ago)\n", st.LastContact.Local().Format(time.RFC3339), time.Since(st.LastContact).Round(time.Second))
			}
			if !st.QuarantinedSince.IsZero() {
				fmt.Fprintf(w, "QUARANTINED\tsince %s: the server rejects the agent token (HTTP 401); allow-list kept, uploads stopped, retrying\n", st.QuarantinedSince.Local().Format(time.RFC3339))
			}
			for _, d := range st.Drivers {
				fmt.Fprintf(w, "driver %s\t%s %s\n", d.Instance, d.State, d.Detail)
			}
			if len(st.Drivers) == 0 {
				fmt.Fprintf(w, "drivers\t(no heartbeat since enrolment)\n")
			}
			return w.Flush()
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "machine-readable output")
	return cmd
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func rotateCmd(load loader) *cobra.Command {
	return &cobra.Command{
		Use:   "rotate-token",
		Short: "Replace the agent token now (the old one stays valid for 10 minutes)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := load()
			if err != nil {
				return err
			}
			if err := agent.RotateToken(cmd.Context(), cfg); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Token rotated. A running service picks it up on its next connection.")
			return nil
		},
	}
}

func configCmd(load loader) *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Configuration tools"}
	cmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Validate agent.yaml and build every driver without opening hardware",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, path, err := load()
			if err != nil {
				return err
			}
			if err := cfg.Validate(driverTypes()); err != nil {
				return err
			}
			for _, dc := range cfg.Drivers {
				reg, _ := driver.Find(Drivers, dc.Type)
				d, err := reg.New(dc.Name, dc.Config, slog.New(slog.DiscardHandler))
				if err != nil {
					return fmt.Errorf("driver %s: %w", dc.Name, err)
				}
				_ = d.Close()
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s: ok (%d driver instances)\n", path, len(cfg.Drivers))
			return nil
		},
	})
	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the agent version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "openbekci-agent %s (commit %s, built %s, %s, %s/%s, protocol v%d)\n",
				version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH, protocol.Version)
		},
	}
}
