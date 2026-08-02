// Package probereport serves the read side of the hivre.com DNS-measurement
// lab: given a token a page generated, report what the visitor's resolver
// actually did.
//
// The write side is a CoreDNS plugin in a different repository under a
// different licence (github.com/puredevotion/coredns-plugins, MIT). The two
// programs share nothing but a Valkey key space — no linked code, no shared
// library — which is deliberate: it keeps that plugin unencumbered by this
// repository's AGPL while still letting one report on the other's observations.
//
// The key format below is therefore a contract with another program. Changing
// it breaks the pairing silently, in the direction that is hardest to notice:
// the page would show "your resolver made no queries", which is also a
// legitimate finding (a resolver that never reached us at all), so nothing
// would look broken.
//
//	probe:seen:<token>     counter, incremented once per query
//	probe:obs:<token>      list of JSON observations, capped
//	probe:reports:<token>  list of JSON RFC 9567 error reports, capped
//
// The counter is separate from the list because the list is capped: past the
// cap the count keeps rising, and "your resolver asked 200 times" is itself
// worth reporting.
//
// The reports key is a third, independent list rather than part of the
// observation stream, because a report arrives on its own schedule: a resolver
// reports after it has given up, and may hold the report query in its cache for
// a TTL before repeating it. A report therefore routinely outlives the
// observations for the same token, and folding the two together would tie its
// retention to a visitor who has already left.
//
// The plugin also keeps a `probe:reports:unattributed` list for reports whose
// name carried no token. That one is deliberately NOT read here — see Get.
package probereport

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/valkey-io/valkey-go"
)

// commandTimeout bounds a single Valkey round-trip. This is a page load, not a
// batch job; a slow store should surface as an error rather than a hung tab.
const commandTimeout = 2 * time.Second

const (
	minTokenLen = 8
	maxTokenLen = 32
)

// Observation mirrors the JSON the probe plugin writes. Only the fields this
// report renders are declared: unknown fields are ignored by encoding/json, so
// the plugin can add observations without a lockstep release here.
type Observation struct {
	Token          string    `json:"token"`
	At             time.Time `json:"at"`
	ResolverAddr   string    `json:"resolver_addr"`
	ResolverPrefix string    `json:"resolver_prefix"`
	Transport      string    `json:"transport"`
	IPv6           bool      `json:"ipv6"`
	Qtype          string    `json:"qtype"`
	Mods           string    `json:"mods"`
	DO             bool      `json:"do"`
	EDNS           bool      `json:"edns"`
	UDPSize        uint16    `json:"udp_size"`
	Cookie         bool      `json:"cookie"`
	ECS            bool      `json:"ecs"`
	ECSScope       uint8     `json:"ecs_scope"`
	ECSFamily      uint16    `json:"ecs_family"`
	ECSPrefix      string    `json:"ecs_prefix"`
	CompactAware   bool      `json:"compact_aware"`
	DELEGAware     bool      `json:"deleg_aware"`
	// KeyTags are the DNSSEC key tags the resolver signalled (RFC 8145). Empty is
	// "said nothing", not "holds none".
	KeyTags []uint16 `json:"key_tags,omitempty"`
	// KnowsZoneKey is meaningful only alongside a non-empty KeyTags.
	KnowsZoneKey bool `json:"knows_zone_key,omitempty"`
	// ZoneVersionAsked means the resolver asked which zone version answered
	// (RFC 9660).
	ZoneVersionAsked bool `json:"zoneversion_asked,omitempty"`
	// TLS is the handshake detail when the query arrived encrypted (RFC 9539),
	// nil for cleartext.
	TLS            *TLSInfo `json:"tls,omitempty"`
	CaseRandomized bool     `json:"case_randomized"`
	Seen           int      `json:"seen"`
}

// TLSInfo mirrors the probe plugin's handshake detail for an encrypted query.
type TLSInfo struct {
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	NamedGroup  string `json:"named_group,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	DidResume   bool   `json:"did_resume,omitempty"`
}

// Encrypted reports whether the query reached us over an encrypted transport
// (RFC 9539). Derived from Transport rather than from TLS being non-nil, so it
// stays correct if a transport is ever added that carries no handshake detail.
func (o Observation) Encrypted() bool {
	switch o.Transport {
	case "tls", "quic", "https":
		return true
	default:
		return false
	}
}

// TrustAnchorReading is three-valued for the same reason DELEGReading is: a
// resolver that signalled no key tags has NOT told us it lacks this zone's key.
type TrustAnchorReading string

const (
	// TrustAnchorSilent means the resolver signalled no key tags at all. This is
	// the overwhelmingly common case and says nothing about what it holds.
	TrustAnchorSilent TrustAnchorReading = "silent"
	// TrustAnchorOurs means this zone's key tag was among those signalled.
	TrustAnchorOurs TrustAnchorReading = "holds-zone-key"
	// TrustAnchorOther means tags were signalled but none was ours.
	TrustAnchorOther TrustAnchorReading = "other-keys-only"
)

// TrustAnchorReading reports the RFC 8145 signal without turning silence into a
// negative finding.
func (o Observation) TrustAnchorReading() TrustAnchorReading {
	switch {
	case len(o.KeyTags) == 0:
		return TrustAnchorSilent
	case o.KnowsZoneKey:
		return TrustAnchorOurs
	default:
		return TrustAnchorOther
	}
}

// ECSDisclosure is the three-state reading of EDNS Client Subnet.
//
// Two states would be wrong, and wrong in the direction that matters: RFC 7871
// §7.1.2 lets a resolver send the option with SOURCE PREFIX-LENGTH 0 to say
// "deliberately disclosing nothing", which is the BEST outcome. Rendering that
// the same as a disclosure would accuse the resolvers behaving well.
type ECSDisclosure string

const (
	// ECSSilent means no option was sent. The resolver told us nothing, which is
	// not the same as declining — it may simply not implement ECS.
	ECSSilent ECSDisclosure = "silent"
	// ECSDeclined means the option was sent with a zero prefix length: an
	// explicit refusal to disclose.
	ECSDeclined ECSDisclosure = "declined"
	// ECSDisclosed means the resolver handed over some bits of the client
	// address.
	ECSDisclosed ECSDisclosure = "disclosed"
)

// ECSDisclosure collapses the ecs/ecs_scope pair into the reading a page should
// show. Kept here rather than in the template so the distinction is testable and
// cannot be re-flattened by whoever next edits the markup.
func (o Observation) ECSDisclosure() ECSDisclosure {
	switch {
	case !o.ECS:
		return ECSSilent
	case o.ECSScope == 0:
		return ECSDeclined
	default:
		return ECSDisclosed
	}
}

// DELEGReading is a three-state answer too, for the same reason: a resolver that
// sent no OPT record at all has not told us it is DELEG-unaware.
type DELEGReading string

const (
	// DELEGUnknown means the query carried no EDNS, so the DE bit could not have
	// been present either way. Absence of evidence.
	DELEGUnknown DELEGReading = "unknown"
	// DELEGUnaware means EDNS was present and the DE bit was not set.
	DELEGUnaware DELEGReading = "unaware"
	// DELEGAwareReading means the resolver set the DE bit.
	DELEGAwareReading DELEGReading = "aware"
)

// DELEGReading reports DELEG-awareness without conflating "did not say" with
// "said no".
//
// Note the underlying bit is a PROVISIONAL assignment in draft-ietf-deleg; see
// the probe plugin's README before drawing conclusions from an aggregate.
func (o Observation) DELEGReading() DELEGReading {
	switch {
	case !o.EDNS:
		return DELEGUnknown
	case o.DELEGAware:
		return DELEGAwareReading
	default:
		return DELEGUnaware
	}
}

// ErrorReport mirrors one RFC 9567 DNS error report as the probe plugin wrote
// it: a resolver telling us, out of band, that it could not resolve one of our
// names and what stopped it.
//
// The interesting field is EDE read against the name that failed. The probe zone
// breaks names in specific, labelled ways, so `_expiredsig...` reported as EDE 7
// (Signature Expired) means the resolver diagnosed correctly, while the same
// name reported as EDE 6 (DNSSEC Bogus) means it noticed but could not say why.
type ErrorReport struct {
	// At is when the report reached the authoritative server, NOT when the
	// failure happened. The gap can be minutes.
	At time.Time `json:"at"`
	// Qtype and Qname are what the resolver says it was trying to resolve.
	Qtype     uint16 `json:"qtype"`
	QtypeName string `json:"qtype_name"`
	Qname     string `json:"qname"`
	// EDE is the RFC 8914 extended error code the resolver concluded.
	EDE uint16 `json:"ede"`
	// EDEText is the registered description, empty for codes the plugin's build
	// did not know. Empty is not an error: the registry grows.
	EDEText string `json:"ede_text,omitempty"`
	// ReporterAddr is the resolver that sent the REPORT, which need not be the
	// address that made the failing query — a pool can report from a different
	// member, and seeing that is worth more than hiding it.
	ReporterAddr   string `json:"reporter_addr"`
	ReporterPrefix string `json:"reporter_prefix"`
	Transport      string `json:"transport"`
}

// Report is the response body.
type Report struct {
	Token string `json:"token"`
	// Queries is how many queries carried this token, which can exceed
	// len(Observations) once the plugin's per-token detail cap is reached.
	Queries      int           `json:"queries"`
	Observations []Observation `json:"observations"`
	// Resolvers is the distinct egress addresses seen, in first-seen order. A
	// resolver pool answers from several addresses, and that is worth showing
	// rather than flattening away.
	Resolvers []string `json:"resolvers"`
	// ErrorReports are the RFC 9567 reports this token's failures provoked,
	// oldest first. Empty is the common case and is NOT a finding: almost no
	// resolver implements the reporting side, reports are lossy, and one can
	// still be in flight. A page must render this as "none received", never as
	// "nothing failed".
	ErrorReports []ErrorReport `json:"error_reports"`
}

// Store reads observations written by the probe plugin.
type Store struct {
	Client valkey.Client
}

func seenKey(token string) string    { return "probe:seen:" + token }
func obsKey(token string) string     { return "probe:obs:" + token }
func reportsKey(token string) string { return "probe:reports:" + token }

// ErrNoStore means no Valkey client was configured, so there is nothing to read.
var ErrNoStore = errors.New("probereport: no valkey client configured")

// Get assembles the report for one token.
//
// A token with nothing recorded is not an error: it is the "your resolver never
// reached us" case, which happens legitimately (a resolver that failed, or a
// browser that never issued the lookups) and is one of the more interesting
// things the page can say.
//
// Only the token's OWN error reports are read. The plugin also keeps an
// unattributed list — reports whose failing name carried no token — and that one
// stays operator-only, visible through the plugin's Prometheus counters and in
// Valkey. Serving it from a token-addressed endpoint would hand every visitor a
// feed of other people's resolvers and the names they failed on, in exchange for
// a number no individual visitor can act on.
func (s *Store) Get(token string) (*Report, error) {
	if s == nil || s.Client == nil {
		return nil, ErrNoStore
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	c := s.Client
	report := &Report{
		Token:        token,
		Observations: []Observation{},
		Resolvers:    []string{},
		ErrorReports: []ErrorReport{},
	}

	if n, err := c.Do(ctx, c.B().Get().Key(seenKey(token)).Build()).AsInt64(); err == nil {
		report.Queries = int(n)
	} else if !valkey.IsValkeyNil(err) {
		return nil, err
	}

	vals, err := c.Do(ctx, c.B().Lrange().Key(obsKey(token)).Start(0).Stop(-1).Build()).AsStrSlice()
	if err != nil && !valkey.IsValkeyNil(err) {
		return nil, err
	}

	seenResolver := make(map[string]bool, len(vals))
	for _, v := range vals {
		var obs Observation
		if err := json.Unmarshal([]byte(v), &obs); err != nil {
			// One unparseable entry must not hide the rest. This is diagnostic
			// data and a partial report beats no report — and a decoding
			// mismatch here is exactly the symptom of the two programs' key
			// contract having drifted, which is worth seeing rather than
			// erroring out over.
			continue
		}
		report.Observations = append(report.Observations, obs)
		if obs.ResolverAddr != "" && !seenResolver[obs.ResolverAddr] {
			seenResolver[obs.ResolverAddr] = true
			report.Resolvers = append(report.Resolvers, obs.ResolverAddr)
		}
	}

	// Queries can legitimately be zero while observations exist only if the
	// counter expired first; keep the larger of the two so the page never
	// reports fewer queries than it is about to list.
	if report.Queries < len(report.Observations) {
		report.Queries = len(report.Observations)
	}

	// Read AFTER the observations and tolerated separately: error reports arrive
	// on their own schedule and can exist for a token whose observations have
	// already expired. Failing the whole report because this key is unreadable
	// would throw away the part that is present.
	reports, err := c.Do(ctx, c.B().Lrange().Key(reportsKey(token)).Start(0).Stop(-1).Build()).AsStrSlice()
	if err != nil && !valkey.IsValkeyNil(err) {
		return nil, err
	}
	for _, v := range reports {
		var er ErrorReport
		if err := json.Unmarshal([]byte(v), &er); err != nil {
			// Same reasoning as the observation loop: a partial report beats
			// none, and a decode mismatch here is the visible symptom of the two
			// programs' key contract drifting.
			continue
		}
		report.ErrorReports = append(report.ErrorReports, er)
	}
	return report, nil
}

// HTTPHandler serves GET /api/report?token=<token>.
type HTTPHandler struct {
	Store *Store
}

// ValidToken reports whether s is a token this zone could have issued: 8-32
// lowercase hex characters, matching the probe plugin's grammar.
//
// Validated before the token reaches Valkey, not after: without this, the query
// string becomes a way to name arbitrary keys in a shared store.
func ValidToken(s string) bool {
	if len(s) < minTokenLen || len(s) > maxTokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func (h *HTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "unsupported method", http.StatusMethodNotAllowed)
		return
	}

	token := req.URL.Query().Get("token")
	if !ValidToken(token) {
		http.Error(w, "invalid or missing \"token\"", http.StatusBadRequest)
		return
	}

	report, err := h.Store.Get(token)
	if err != nil {
		if errors.Is(err, ErrNoStore) {
			http.Error(w, "reporting is not configured", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	// No CORS header at all: this endpoint is read by our own page from our own
	// origin. Opening it up would let any site enumerate tokens through a
	// visitor's browser, and a token is the handle to someone's resolver
	// fingerprint.
	w.Header().Set("Content-Type", "application/json")
	// Never cached: the whole point is that the answer changes as the visitor's
	// resolver makes queries, and a cached empty report is indistinguishable
	// from a resolver that failed.
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(report)
}
