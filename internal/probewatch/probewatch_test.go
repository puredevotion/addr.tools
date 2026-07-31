package probewatch

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/brianshea2/addr.tools/internal/probereport"
	"github.com/brianshea2/addr.tools/internal/zones/dnscheck"
)

// captureWatcher records what would have gone out over the websocket.
type captureWatcher struct {
	mu   sync.Mutex
	msgs []captured
}

type captured struct {
	req   *dns.Msg
	proto string
	raddr net.Addr
}

func (c *captureWatcher) Send(req *dns.Msg, proto string, raddr net.Addr, _ *tls.ConnectionState) {
	c.mu.Lock()
	c.msgs = append(c.msgs, captured{req, proto, raddr})
	c.mu.Unlock()
}

func (c *captureWatcher) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

// TestCursorAdvancesPastUndecodableEntries is the bookkeeping that would break
// quietly. An entry that fails to decode must NOT be forwarded (a fabricated
// empty observation would draw a phantom query on the page and bump its counter),
// but it MUST still advance the cursor, or the tail re-reads it every tick
// forever and never reaches anything after it.
func TestCursorAdvancesPastUndecodableEntries(t *testing.T) {
	var (
		mu      sync.Mutex
		cursors []int64
	)
	h := &Hub{
		Inner:    &dnscheck.SimpleWatcherHub{MaxSize: 10},
		Interval: time.Millisecond,
		Zone:     "check.example.com",
	}
	// Batch 1: three list entries, only two of which decode.
	h.fetchFn = func(_ context.Context, _ string, cursor int64) ([]probereport.Observation, int, error) {
		mu.Lock()
		cursors = append(cursors, cursor)
		n := len(cursors)
		mu.Unlock()
		if n == 1 {
			return []probereport.Observation{
				{Token: "deadbeef", Qtype: "TXT", ResolverAddr: "192.0.2.1", Transport: "udp"},
				{Token: "deadbeef", Qtype: "A", ResolverAddr: "192.0.2.2", Transport: "udp"},
			}, 3, nil // 3 consumed, 1 was undecodable
		}
		return nil, 0, nil
	}

	w := &captureWatcher{}
	if err := h.Register("deadbeef", w); err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer h.Unregister("deadbeef")

	waitFor(t, func() bool { return w.count() >= 2 })

	if got := w.count(); got != 2 {
		t.Errorf("sent %d messages, want 2 (the undecodable entry must not be forwarded)", got)
	}

	// The next poll must start at 3, not 2.
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(cursors) >= 2
	})
	mu.Lock()
	second := cursors[1]
	mu.Unlock()
	if second != 3 {
		t.Errorf("second poll started at cursor %d, want 3 (consumed, not sent)", second)
	}
}

// TestNoResendOnRepeatedPolls — the cursor exists so the SPA is not shown the
// same query over and over, which would inflate its visible query count and make
// one resolver look like many requests.
func TestNoResendOnRepeatedPolls(t *testing.T) {
	h := &Hub{
		Inner:    &dnscheck.SimpleWatcherHub{MaxSize: 10},
		Interval: time.Millisecond,
	}
	h.fetchFn = func(_ context.Context, _ string, cursor int64) ([]probereport.Observation, int, error) {
		if cursor == 0 {
			return []probereport.Observation{
				{Token: "t", Qtype: "TXT", ResolverAddr: "192.0.2.1", Transport: "udp"},
			}, 1, nil
		}
		return nil, 0, nil
	}

	w := &captureWatcher{}
	if err := h.Register("t", w); err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer h.Unregister("t")

	waitFor(t, func() bool { return w.count() >= 1 })
	time.Sleep(40 * time.Millisecond) // many ticks at 1ms

	if got := w.count(); got != 1 {
		t.Errorf("sent %d messages after repeated polls, want exactly 1", got)
	}
}

// TestFetchErrorDoesNotKillTail — a store blip must degrade liveness, not leave
// the page permanently silent until reload.
func TestFetchErrorDoesNotKillTail(t *testing.T) {
	var calls int
	var mu sync.Mutex
	h := &Hub{
		Inner:    &dnscheck.SimpleWatcherHub{MaxSize: 10},
		Interval: time.Millisecond,
	}
	h.fetchFn = func(_ context.Context, _ string, _ int64) ([]probereport.Observation, int, error) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n < 3 {
			return nil, 0, errors.New("valkey down")
		}
		return []probereport.Observation{
			{Token: "t", Qtype: "TXT", ResolverAddr: "192.0.2.1", Transport: "udp"},
		}, 1, nil
	}

	w := &captureWatcher{}
	if err := h.Register("t", w); err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer h.Unregister("t")

	waitFor(t, func() bool { return w.count() >= 1 })
}

// TestRegisterFailureStartsNoTail — the inner hub refuses at max size, so there
// is nobody to send to. Starting a tail anyway is how a rejected connection turns
// into a leaked goroutine.
func TestRegisterFailureStartsNoTail(t *testing.T) {
	h := &Hub{Inner: &dnscheck.SimpleWatcherHub{MaxSize: 1}, Interval: time.Millisecond}
	h.fetchFn = func(context.Context, string, int64) ([]probereport.Observation, int, error) {
		return nil, 0, nil
	}

	if err := h.Register("first", &captureWatcher{}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	defer h.Unregister("first")

	if err := h.Register("second", &captureWatcher{}); err == nil {
		t.Fatal("second Register succeeded past MaxSize")
	}
	if got := h.Tails(); got != 1 {
		t.Errorf("Tails() = %d after a rejected Register, want 1", got)
	}
}

// TestUnregisterStopsTail guards the other half of the leak: one goroutine per
// open page means they must end when the page does.
func TestUnregisterStopsTail(t *testing.T) {
	h := &Hub{Inner: &dnscheck.SimpleWatcherHub{MaxSize: 10}, Interval: time.Millisecond}

	var mu sync.Mutex
	var polling bool
	h.fetchFn = func(context.Context, string, int64) ([]probereport.Observation, int, error) {
		mu.Lock()
		polling = true
		mu.Unlock()
		return nil, 0, nil
	}

	if err := h.Register("t", &captureWatcher{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	waitFor(t, func() bool { mu.Lock(); defer mu.Unlock(); return polling })

	h.Unregister("t")
	if got := h.Tails(); got != 0 {
		t.Errorf("Tails() = %d after Unregister, want 0", got)
	}
	if h.Inner.IsRegistered("t") {
		t.Error("watcher still registered with the inner hub after Unregister")
	}

	mu.Lock()
	polling = false
	mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	mu.Lock()
	stillPolling := polling
	mu.Unlock()
	if stillPolling {
		t.Error("tail kept polling after Unregister")
	}
}

// TestQueryNameReconstruction pins the display name. Modifiers are stored
// comma-joined without their leading underscore, so they have to be put back
// into label form.
func TestQueryNameReconstruction(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  probereport.Observation
		zone string
		want string
	}{
		{"bare token", probereport.Observation{Token: "deadbeef"}, "check.example.com", "deadbeef.check.example.com."},
		{"mods none", probereport.Observation{Token: "deadbeef", Mods: "none"}, "check.example.com", "deadbeef.check.example.com."},
		{"one mod", probereport.Observation{Token: "deadbeef", Mods: "badsig"}, "check.example.com", "_badsig.deadbeef.check.example.com."},
		{"two mods", probereport.Observation{Token: "deadbeef", Mods: "unsigned,big"}, "check.example.com", "_unsigned._big.deadbeef.check.example.com."},
		// Question[0] is dereferenced unconditionally by upstream's encoder, so
		// there must always be a name.
		{"nothing at all", probereport.Observation{}, "", "."},
	} {
		if got := queryName(tc.obs, tc.zone); got != tc.want {
			t.Errorf("%s: queryName = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestRemoteAddrIsRenderable is subtle and load-bearing: upstream's encoder
// switches only on *net.UDPAddr and *net.TCPAddr, so any other type silently
// yields an empty remoteIp — and remoteIp is how the SPA identifies resolvers,
// making it the single most important field in the message.
func TestRemoteAddrIsRenderable(t *testing.T) {
	for _, transport := range []string{"udp", "tcp", "tls", "quic", "https", ""} {
		obs := probereport.Observation{ResolverAddr: "192.0.2.53", Transport: transport}
		switch a := remoteAddr(obs).(type) {
		case *net.UDPAddr:
			if a.IP.String() != "192.0.2.53" {
				t.Errorf("%s: IP = %v", transport, a.IP)
			}
		case *net.TCPAddr:
			if a.IP.String() != "192.0.2.53" {
				t.Errorf("%s: IP = %v", transport, a.IP)
			}
		default:
			t.Errorf("%s: remoteAddr returned %T, which upstream's encoder renders as an empty remoteIp", transport, a)
		}
	}
}

// TestSynthesizeECSThreeStates checks the field the SPA reads for ECS, across all
// three states. The SPA skips a clientSubnet ending in "/0", so a resolver that
// explicitly declined must render that way rather than as a disclosure — and a
// resolver that said nothing must produce no clientSubnet at all.
func TestSynthesizeECSThreeStates(t *testing.T) {
	base := probereport.Observation{
		Token: "deadbeef", Qtype: "TXT", ResolverAddr: "192.0.2.53",
		Transport: "udp", EDNS: true, UDPSize: 1232,
	}

	t.Run("silent", func(t *testing.T) {
		req, _, _, _ := synthesize(base, "check.example.com")
		if sub := findSubnet(req); sub != nil {
			t.Errorf("clientSubnet option present for a silent resolver: %+v", sub)
		}
	})

	t.Run("declined renders /0", func(t *testing.T) {
		o := base
		o.ECS, o.ECSScope, o.ECSFamily = true, 0, 1
		req, _, _, _ := synthesize(o, "check.example.com")
		sub := findSubnet(req)
		if sub == nil {
			t.Fatal("clientSubnet option absent for a declining resolver")
		}
		if sub.SourceNetmask != 0 {
			t.Errorf("SourceNetmask = %d, want 0 so the SPA skips it as a non-disclosure", sub.SourceNetmask)
		}
	})

	t.Run("disclosed", func(t *testing.T) {
		o := base
		o.ECS, o.ECSScope, o.ECSFamily, o.ECSPrefix = true, 24, 1, "198.51.100.0/24"
		req, _, _, _ := synthesize(o, "check.example.com")
		sub := findSubnet(req)
		if sub == nil {
			t.Fatal("clientSubnet option absent for a disclosing resolver")
		}
		if sub.SourceNetmask != 24 {
			t.Errorf("SourceNetmask = %d, want 24", sub.SourceNetmask)
		}
		if sub.Address.String() != "198.51.100.0" {
			t.Errorf("Address = %v, want 198.51.100.0", sub.Address)
		}
	})
}

// TestSynthesizeCarriesEDNSState checks the remaining fields the SPA consumes.
func TestSynthesizeCarriesEDNSState(t *testing.T) {
	t.Run("no edns", func(t *testing.T) {
		o := probereport.Observation{Token: "t", Qtype: "A", ResolverAddr: "192.0.2.1", Transport: "udp"}
		req, _, _, _ := synthesize(o, "check.example.com")
		if req.IsEdns0() != nil {
			t.Error("OPT record synthesized for a query that carried none")
		}
	})

	t.Run("edns with do", func(t *testing.T) {
		o := probereport.Observation{
			Token: "t", Qtype: "A", ResolverAddr: "192.0.2.1", Transport: "udp",
			EDNS: true, UDPSize: 4096, DO: true,
		}
		req, proto, _, _ := synthesize(o, "check.example.com")
		opt := req.IsEdns0()
		if opt == nil {
			t.Fatal("no OPT record")
		}
		if opt.UDPSize() != 4096 {
			t.Errorf("UDPSize = %d, want 4096", opt.UDPSize())
		}
		if !opt.Do() {
			t.Error("DO bit not set")
		}
		if proto != "udp" {
			t.Errorf("proto = %q, want udp", proto)
		}
	})

	t.Run("unknown qtype does not panic", func(t *testing.T) {
		o := probereport.Observation{Token: "t", Qtype: "TYPE65123", ResolverAddr: "192.0.2.1", Transport: "udp"}
		req, _, _, _ := synthesize(o, "check.example.com")
		if len(req.Question) != 1 {
			t.Fatal("no question section")
		}
	})
}

func findSubnet(m *dns.Msg) *dns.EDNS0_SUBNET {
	opt := m.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		if s, ok := o.(*dns.EDNS0_SUBNET); ok {
			return s
		}
	}
	return nil
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition not met within 2s")
}
