package transport

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/openbekci/openbekci-agent/internal/protocol"
)

func ackEnv(t *testing.T) protocol.Envelope {
	t.Helper()
	a, err := protocol.NewAck(protocol.NewID(), protocol.AckOK, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := protocol.New(protocol.TypeAck, a, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func bareSession(holeTTL time.Duration) (*pollSession, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{o: Options{Log: slog.New(slog.DiscardHandler), PollHoleTimeout: holeTTL}}
	return newPollSession(c, ctx), cancel
}

// Responses of concurrent requests can arrive in any order; messages are still
// delivered in the server's sequence.
func TestPollDeliversInServerSequenceOrder(t *testing.T) {
	p, cancel := bareSession(0)
	defer cancel()
	envs := []protocol.Envelope{ackEnv(t), ackEnv(t), ackEnv(t), ackEnv(t)}
	var wg sync.WaitGroup
	for _, i := range []int{3, 1, 2, 0} { // arrival order: seq 4, 2, 3, 1
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(len(envs)-i) * 5 * time.Millisecond)
			p.accept(protocol.Poll{Messages: []protocol.Envelope{envs[i]}, Seq: int64(i + 1)})
		}()
	}
	wg.Wait()
	for i, want := range envs {
		got, err := p.Receive(context.Background())
		if err != nil || got.ID != want.ID {
			t.Fatalf("message %d: got %s (%v), want %s", i, got.ID, err, want.ID)
		}
	}
	// A duplicate of an already delivered sequence number is ignored.
	p.accept(protocol.Poll{Messages: []protocol.Envelope{ackEnv(t)}, Seq: 2})
	select {
	case m := <-p.in:
		t.Fatalf("duplicate delivered: %s", m.ID)
	default:
	}
}

func TestPollSequenceHoleRestartsTheSession(t *testing.T) {
	p, cancel := bareSession(50 * time.Millisecond)
	defer cancel()
	p.accept(protocol.Poll{Messages: []protocol.Envelope{ackEnv(t)}, Seq: 2}) // seq 1 never arrives
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if _, err := p.Receive(ctx); !errors.Is(err, errSequenceHole) {
		t.Fatalf("Receive: %v, want the sequence-hole error", err)
	}
}

// Acks of a multi-part snapshot and friends go out in a few requests, not one
// request each.
func TestPollCoalescesSends(t *testing.T) {
	e := newEnv(t, nil)
	e.fs.FailUpgrades(-1)
	e.client.o.WSRetry = time.Hour
	sent := make(chan struct{})
	h := func(ctx context.Context, s Session) error {
		if err := s.Send(ctx, hello(t)); err != nil {
			return err
		}
		var wg sync.WaitGroup
		for range 30 {
			wg.Add(1)
			go func() { defer wg.Done(); _ = s.Send(ctx, ackEnv(t)) }()
		}
		wg.Wait()
		close(sent)
		<-ctx.Done()
		return ctx.Err()
	}
	cancel, _ := run(e, h)
	defer cancel()
	select {
	case <-sent:
	case <-time.After(15 * time.Second):
		t.Fatal("sends did not complete")
	}
	if !e.fs.Eventually(5*time.Second, func() bool { return len(e.fs.Acks()) == 30 }) {
		t.Fatalf("server saw %d acks, want 30", len(e.fs.Acks()))
	}
	if n := e.fs.PollRequests(); n > 4 {
		t.Fatalf("%d send requests for 30 acks, want them coalesced (<= 4)", n)
	}
}
