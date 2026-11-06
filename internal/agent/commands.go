package agent

import (
	"encoding/json"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
	"github.com/openbekci/openbekci-agent/internal/transport"
)

// storedResult is what the command replay cache keeps: enough to answer a
// re-delivered command with the same ack.
type storedResult struct {
	Status string         `json:"status"`
	Detail map[string]any `json:"detail,omitempty"`
}

func (s *sessState) onCommand(env protocol.Envelope, c *protocol.Command) error {
	switch c.Command {
	case protocol.CmdOpenPoint:
		s.openPoint(env, c)
	case protocol.CmdRevokeCredential:
		removed, err := s.a.st.RemoveEntry(s.ctx, c.CredentialID)
		if err != nil {
			s.ack(env.ID, protocol.AckError, map[string]string{"reason": "store error"})
			return err
		}
		s.ack(env.ID, protocol.AckOK, map[string]any{"removed": removed})
	case protocol.CmdRequestSnapshot:
		// Snapshots always replace the store; the server follows up with one.
		s.ack(env.ID, protocol.AckOK, nil)
	case protocol.CmdUpdateConfig:
		return s.updateConfig(env, c)
	case protocol.CmdRevoked:
		// The 4401 close follows; Run wipes the state when it sees ErrRevoked.
		s.a.log.Warn("server sent command revoked")
		return transport.ErrRevoked
	default:
		s.ack(env.ID, protocol.AckUnsupported, nil)
	}
	return nil
}

func (s *sessState) updateConfig(env protocol.Envelope, c *protocol.Command) error {
	cfg := c.Config()
	if _, err := time.LoadLocation(cfg.Site.Timezone); err != nil {
		s.ack(env.ID, protocol.AckError, map[string]string{"reason": "unknown timezone"})
		return nil
	}
	if cfg.Points == nil {
		cfg.Points = []protocol.PointConfig{}
	}
	if err := s.a.st.SaveConfig(s.ctx, cfg); err != nil {
		s.ack(env.ID, protocol.AckError, map[string]string{"reason": "store error"})
		return err
	}
	s.a.mu.Lock()
	s.a.pcfg = cfg
	s.a.mu.Unlock()
	s.a.refreshSettings(s.ctx)
	s.ack(env.ID, protocol.AckOK, map[string]any{"config_version": cfg.ConfigVersion})
	s.checkReady()
	// Missing driver instances show up in the next heartbeat.
	for _, d := range s.a.driverStates(s.ctx) {
		if d.State == "missing" {
			s.a.log.Warn("point references a driver instance missing from agent.yaml", "instance", d.Instance)
		}
	}
	return nil
}

// openPoint handles command open_point: replay protection, 15 s TTL, one
// pulse, no automatic retry.
func (s *sessState) openPoint(env protocol.Envelope, c *protocol.Command) {
	a := s.a
	if raw, ok, err := a.st.CommandResult(s.ctx, env.ID, a.now()); err != nil {
		s.ack(env.ID, protocol.AckError, map[string]string{"reason": "store error"})
		return
	} else if ok {
		var r storedResult
		if json.Unmarshal(raw, &r) == nil {
			a.log.Info("command re-delivered, answering from cache", "command_id", env.ID, "status", r.Status)
			s.ack(env.ID, r.Status, r.Detail)
			return
		}
	}

	finish := func(status string, detail map[string]any) {
		raw, _ := json.Marshal(storedResult{Status: status, Detail: detail})
		if err := a.st.RecordCommand(s.ctx, env.ID, raw, a.now()); err != nil {
			a.log.Error("record command result", "error", err)
		}
		s.ack(env.ID, status, detail)
	}

	// Expiry is judged on the server's timeline (agent clock + measured
	// offset), and the TTL is capped at 60 s whatever expires_at says.
	expires := c.ExpiresAt.Time
	if limit := c.IssuedAt.Add(maxCommandTTL); expires.After(limit) {
		expires = limit
	}
	if a.serverNow().After(expires) {
		a.log.Warn("open command expired, not executing", "command_id", env.ID)
		finish(protocol.AckExpired, map[string]any{"reason": "ttl"})
		return
	}
	p, ok := a.point(c.PointID)
	switch {
	case !ok:
		finish(protocol.AckUnknownPoint, map[string]any{"reason": "unknown_point"})
		return
	case !p.Enabled:
		finish(protocol.AckRefused, map[string]any{"reason": "point_disabled"})
		return
	}

	// Write a provisional result first: if the process dies mid-pulse, a
	// re-delivery must not open the gate a second time.
	prov, _ := json.Marshal(storedResult{Status: protocol.AckFailed, Detail: map[string]any{"reason": "interrupted"}})
	if err := a.st.RecordCommand(s.ctx, env.ID, prov, a.now()); err != nil {
		a.log.Error("record command", "error", err)
		s.ack(env.ID, protocol.AckError, map[string]string{"reason": "store error"})
		return
	}
	if err := a.openPoint(s.ctx, c.PointID); err != nil {
		a.log.Error("open command failed", "command_id", env.ID, "point_id", c.PointID, "error", err)
		finish(protocol.AckFailed, map[string]any{"reason": "driver_error", "message": truncate(err.Error(), 200)})
		return
	}
	ev := protocol.Event{
		ID: protocol.NewID(), PointID: c.PointID, Decision: protocol.DecisionManualOpen, Reason: "guard",
		CredentialID: c.CredentialID, VisitorEntryID: c.VisitorEntryID, CommandID: env.ID, OccurredAt: protocol.At(a.now()),
	}
	if _, err := a.st.Enqueue(s.ctx, ev, a.now()); err != nil {
		a.log.Error("queue manual_open event", "error", err)
	}
	a.log.Info("point opened by command", "command_id", env.ID, "point_id", c.PointID, "actor", actorLabel(c.Actor))
	finish(protocol.AckDone, nil)
	a.notifyFlush()
}

func actorLabel(a *protocol.Actor) string {
	if a == nil {
		return ""
	}
	return a.UserID // ids only: names are PII
}
