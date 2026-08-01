// Package probewatch feeds the dnscheck websocket hub from the probe plugin's
// Valkey store, so upstream's /watch endpoint and the UNMODIFIED SPA work
// against this lab's probe zone.
//
// # Why a feeder and not a new endpoint
//
// The SPA opens a websocket and waits for observations to be pushed; it does not
// poll. Upstream's websocket handler, watcher hub and JSON encoder already exist
// in this fork and are exactly what the SPA expects — what went missing is the
// PUBLISHER, because the DNS side moved out to CoreDNS (see "fork is the web tier
// only"). CoreDNS's probe plugin writes observations to Valkey instead of calling
// a Go interface in this process.
//
// So this package supplies the missing publisher rather than a second websocket
// implementation: it reads Valkey and calls the same Watcher.Send upstream's DNS
// handler used to call. The consequence worth having is that message encoding
// stays upstream's WebsocketWatcherMessage.MarshalJSON — byte-identical to what
// the SPA already parses — so neither the JS nor any upstream Go file is touched,
// and the fork keeps its "close to upstream" property.
//
// The cost, stated plainly: polling. The plugin only writes keys, so there is no
// push to subscribe to. Server-side polling is converted into client-side push,
// which is the right place for the poll to live — one goroutine per open page,
// not one request per page per interval from the browser.
package probewatch

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/valkey-io/valkey-go"

	"github.com/brianshea2/addr.tools/internal/probereport"
	"github.com/brianshea2/addr.tools/internal/zones/dnscheck"
)

const (
	// DefaultInterval is how often a watcher's token is polled. The SPA runs a
	// burst of queries and expects them to appear promptly, so this is tuned for
	// perceived liveness rather than for load: one small LRANGE per open page.
	DefaultInterval = 400 * time.Millisecond
	// commandTimeout bounds one Valkey round-trip. A slow store must not wedge a
	// tail goroutine for the life of the websocket.
	commandTimeout = 2 * time.Second
	// maxPerPoll caps how many observations are drained in one tick. A resolver
	// pool can produce a burst; draining it in bounded chunks keeps a single
	// tick's work predictable.
	maxPerPoll = 64
)

func obsKey(token string) string { return "probe:obs:" + token }

// Hub implements dnscheck.WatcherHub by delegating to an inner hub, and starts a
// Valkey tail for each watcher while it is registered.
//
// Implementing the interface rather than being wired alongside it is deliberate:
// the hub's Register/Unregister already mark exactly the lifetime a tail should
// have, and the alternative (adding a List method to SimpleWatcherHub so a
// separate poller could enumerate watchers) would mean editing an upstream file
// to learn something the interface already tells us.
type Hub struct {
	// Inner is the real hub the websocket handler reads from. Required.
	Inner dnscheck.WatcherHub
	// Client is the Valkey client observations are read from. Required.
	Client valkey.Client
	// Zone is the probe zone, used only to reconstruct a display query name.
	// Optional.
	Zone string
	// Interval overrides DefaultInterval.
	Interval time.Duration

	// fetchFn overrides the Valkey read. Exists so the cursor bookkeeping in
	// tail — the part where "entries consumed" must diverge from "observations
	// sent" — can be tested without standing up a Valkey.
	fetchFn func(ctx context.Context, token string, cursor int64) ([]probereport.Observation, int, error)

	mu    sync.Mutex
	tails map[string]chan struct{}
}

func (h *Hub) Get(watcherId string) dnscheck.Watcher { return h.Inner.Get(watcherId) }
func (h *Hub) IsRegistered(watcherId string) bool    { return h.Inner.IsRegistered(watcherId) }

// Register registers the watcher with the inner hub and, on success, starts
// tailing its token.
func (h *Hub) Register(watcherId string, watcher dnscheck.Watcher) error {
	if err := h.Inner.Register(watcherId, watcher); err != nil {
		// Do NOT start a tail: the inner hub refused (usually at max size), so
		// there is nobody to send to. Starting one anyway is how a rejected
		// connection turns into a goroutine leak.
		return err
	}

	// A stop channel rather than a cancellable context. The tail's lifetime is
	// owned by Register/Unregister, not by a deadline or a caller's request
	// scope, and a context whose cancel func escapes the function that made it is
	// both harder to reason about and flagged by gosec G118 for exactly that
	// reason. Closing a channel says "this one is finished" with no ambiguity
	// about who is responsible for calling what.
	stop := make(chan struct{})

	h.mu.Lock()
	if h.tails == nil {
		h.tails = make(map[string]chan struct{})
	}
	// Registering an id that already has a tail should be impossible — the
	// handler checks IsRegistered first — but if it happens, stop the old one
	// rather than orphaning it.
	if old, exists := h.tails[watcherId]; exists {
		close(old)
	}
	h.tails[watcherId] = stop
	h.mu.Unlock()

	go h.tail(stop, watcherId, watcher)
	return nil
}

// Unregister stops the tail and unregisters the watcher.
func (h *Hub) Unregister(watcherId string) {
	h.mu.Lock()
	if stop, exists := h.tails[watcherId]; exists {
		close(stop)
		delete(h.tails, watcherId)
	}
	h.mu.Unlock()
	h.Inner.Unregister(watcherId)
}

// Tails reports how many tail goroutines are live. For tests and status.
func (h *Hub) Tails() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.tails)
}

func (h *Hub) interval() time.Duration {
	if h.Interval > 0 {
		return h.Interval
	}
	return DefaultInterval
}

// tail polls one token's observation list and forwards anything new.
//
// The cursor is an index into the Valkey list, which the plugin only ever RPUSHes
// to, so "everything after what we have already sent" is LRANGE cursor..-1. That
// keeps the tail idempotent under a missed tick and stops it re-sending the
// backlog on every poll, which would show the SPA the same query repeatedly and
// inflate its query counter.
func (h *Hub) tail(stop <-chan struct{}, token string, watcher dnscheck.Watcher) {
	ticker := time.NewTicker(h.interval())
	defer ticker.Stop()

	cursor := int64(0)
	for {
		// Checked FIRST and non-blocking, before any work. The wait select at the
		// bottom is not sufficient on its own: `select` chooses UNIFORMLY AT RANDOM
		// between ready cases, so once the ticker and stop are both ready it will
		// keep choosing another poll roughly half the time. That made shutdown
		// probabilistic rather than prompt — caught by a test asserting polling
		// actually ceases, not by the race detector.
		select {
		case <-stop:
			return
		default:
		}

		// Poll immediately on entry: the SPA fires its first queries as soon as
		// the socket opens, and waiting a full interval first would make the
		// page look dead for no reason.
		obs, consumed, err := h.read(context.Background(), token, cursor)
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}
			// A store hiccup degrades liveness; it must not kill the tail, or a
			// single blip would leave the page silent until reload.
			log.Printf("[warn] probewatch: reading observations for a watcher: %v", err)
		} else {
			for _, o := range obs {
				watcher.Send(synthesize(o, h.Zone))
			}
			// Advance by entries CONSUMED, not by entries sent: an undecodable
			// entry is skipped but must still move the cursor, or the tail
			// re-reads it every tick forever and never reaches what follows.
			cursor += int64(consumed)
		}

		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func (h *Hub) read(ctx context.Context, token string, cursor int64) ([]probereport.Observation, int, error) {
	if h.fetchFn != nil {
		return h.fetchFn(ctx, token, cursor)
	}
	return h.fetch(ctx, token, cursor)
}

// fetch reads up to maxPerPoll observations starting at cursor. It returns the
// decodable observations and the number of list entries consumed, which differ
// when an entry fails to decode — see the cursor handling in tail.
func (h *Hub) fetch(ctx context.Context, token string, cursor int64) ([]probereport.Observation, int, error) {
	if h.Client == nil {
		return nil, 0, nil
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	c := h.Client
	vals, err := c.Do(ctx,
		c.B().Lrange().Key(obsKey(token)).Start(cursor).Stop(cursor+maxPerPoll-1).Build(),
	).AsStrSlice()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			// No key yet: the visitor's resolver has not reached us. Normal, and
			// not an error.
			return nil, 0, nil
		}
		return nil, 0, err
	}

	out := make([]probereport.Observation, 0, len(vals))
	for _, v := range vals {
		var o probereport.Observation
		if err := json.Unmarshal([]byte(v), &o); err != nil {
			// Skipped, NOT forwarded as a zero value: sending a fabricated empty
			// observation would draw a phantom query on the page and bump its
			// query counter for something that never happened. The entry is still
			// counted as consumed by the caller so the tail advances past it.
			log.Printf("[warn] probewatch: undecodable observation: %v", err)
			continue
		}
		out = append(out, o)
	}
	return out, len(vals), nil
}

// synthesize converts an observation into the arguments upstream's
// Watcher.Send expects, reconstructing enough of a DNS query for
// WebsocketWatcherMessage.MarshalJSON to render the fields the SPA reads.
//
// This is a reconstruction, not a recording: the plugin stores the properties of
// the query, not the query bytes. Everything the SPA consumes (qname, qtype,
// remoteIp, isEdns0, udpSize, clientSubnet) is reproduced faithfully; the
// message text under the "full" subprotocol will be a synthesized query rather
// than the original wire form, which is a debugging nicety and not something the
// page's logic depends on.
func synthesize(o probereport.Observation, zone string) (*dns.Msg, string, net.Addr, *tls.ConnectionState) {
	qtype, ok := dns.StringToType[o.Qtype]
	if !ok {
		qtype = dns.TypeNULL
	}

	m := new(dns.Msg)
	m.SetQuestion(queryName(o, zone), qtype)

	if o.EDNS {
		size := o.UDPSize
		if size == 0 {
			size = dns.MinMsgSize
		}
		m.SetEdns0(size, o.DO)
		if opt := m.IsEdns0(); opt != nil && o.ECS {
			// Rendered by upstream as "<address>/<sourceNetmask>". The declined
			// case (option present, prefix length 0) therefore renders ending in
			// "/0", which the SPA already skips — so a resolver that explicitly
			// disclosed nothing is not shown as leaking. That is the correct
			// outcome and the reason ECSPrefix is left empty for it upstream in
			// the plugin.
			sub := &dns.EDNS0_SUBNET{
				Code:          dns.EDNS0SUBNET,
				Family:        o.ECSFamily,
				SourceNetmask: o.ECSScope,
			}
			if o.ECSPrefix != "" {
				// ECSPrefix is CIDR text ("198.51.100.0/24"); the option carries
				// the address, with the length in SourceNetmask already.
				if ip, _, err := net.ParseCIDR(o.ECSPrefix); err == nil {
					sub.Address = ip
				}
			}
			if sub.Family == 0 {
				// Family is required for the option to be meaningful; infer it
				// from the address rather than emitting a zero.
				if sub.Address.To4() != nil {
					sub.Family = 1
				} else if sub.Address != nil {
					sub.Family = 2
				}
			}
			opt.Option = append(opt.Option, sub)
		}
	}

	return m, string(o.Transport), remoteAddr(o), nil
}

// queryName reconstructs a display name of the form [_mod.]<token>.<zone>.
//
// Modifiers are stored comma-joined and without their leading underscore
// ("badsig", "unsigned,big"), so they are put back into label form here. "none"
// means no modifier labels.
func queryName(o probereport.Observation, zone string) string {
	var labels []string
	if o.Mods != "" && o.Mods != "none" {
		for _, mod := range strings.Split(o.Mods, ",") {
			if mod = strings.TrimSpace(mod); mod != "" {
				labels = append(labels, "_"+mod)
			}
		}
	}
	if o.Token != "" {
		labels = append(labels, o.Token)
	}
	name := strings.Join(labels, ".")
	if zone != "" {
		if name == "" {
			name = zone
		} else {
			name += "." + dns.Fqdn(zone)
		}
	}
	if name == "" {
		// MarshalJSON dereferences Question[0] unconditionally, so there must
		// always be a question. The root is the only safe placeholder.
		return "."
	}
	return dns.Fqdn(name)
}

// remoteAddr builds the address type upstream's encoder can render. It switches
// only on *net.UDPAddr and *net.TCPAddr, so anything else would silently produce
// an empty remoteIp — and remoteIp is how the SPA identifies resolvers, i.e. the
// single most important field in the message.
func remoteAddr(o probereport.Observation) net.Addr {
	ip := net.ParseIP(o.ResolverAddr)
	switch o.Transport {
	case "udp", "quic":
		return &net.UDPAddr{IP: ip}
	default:
		return &net.TCPAddr{IP: ip}
	}
}
