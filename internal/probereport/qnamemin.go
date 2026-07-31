package probereport

// RFC 7816 — QNAME minimisation, inferred from the authoritative side.
//
// A minimising resolver does not send the full name it was asked for. It walks
// left to right, querying progressively longer names to find each delegation, and
// only then asks for the name the client wanted. The privacy win is that
// intermediate servers never see the full name.
//
// It is normally described as unobservable from outside the resolver. It is not,
// if you are the authoritative server and the client-side name is unique: the
// minimisation steps arrive as separate queries for SHORTER names, moments before
// the real one, from the same resolver.
//
// # Why this lives here and not in the plugin
//
// The plugin's Observation is deliberately a pure function of ONE query — its own
// documentation says nothing is inferred across queries except the per-token
// counter. Minimisation is only visible in the SEQUENCE, so inferring it there
// would break that property for the sake of one field. The plugin records the
// query type faithfully; this reads the pattern.
//
// # The signal, and its limits
//
// The page asks for names like `_badsig.<token>.<zone>`. A minimising resolver
// therefore queries `<token>.<zone>` first, and RFC 7816 §2 says it does so with
// **QTYPE=NS** by default.
//
// That is the reliable signal, because the page itself never asks for NS. A
// `mods=none, qtype=NS` observation on a token whose page only requested modified
// names can only have come from the resolver's own walk.
//
// The RELAXED variant (some implementations minimise with QTYPE=A instead) is
// NOT distinguishable here, because the page legitimately queries A on the bare
// token as part of its own measurements. So A-based minimisation reads as
// "unknown", never as "no". Reporting it as absent would be a false negative
// dressed up as a finding, and would specifically penalise resolvers that DO
// minimise, just in the relaxed style.
type QNAMEMinimisation string

const (
	// QMinUnknown means the observations cannot answer the question. Either too
	// few queries arrived, or the only evidence available is the ambiguous
	// A-query kind. Not a negative result.
	QMinUnknown QNAMEMinimisation = "unknown"
	// QMinObserved means an intermediate-name NS query arrived, which only a
	// minimising resolver sends.
	QMinObserved QNAMEMinimisation = "observed"
	// QMinAbsent means the resolver asked for modified names directly with no
	// intermediate NS query, having had the opportunity to minimise.
	QMinAbsent QNAMEMinimisation = "absent"
)

// QNAMEMinimisation reports whether the resolver minimised, across all
// observations for one token.
//
// Requires at least one query for a MODIFIED name: that is what creates a shorter
// intermediate name to walk through. A token whose page only ever asked for the
// bare `<token>.<zone>` gives a resolver nothing to minimise within this zone, so
// the answer is unknown rather than absent — the resolver was never given the
// chance to demonstrate either way.
func (r *Report) QNAMEMinimisation() QNAMEMinimisation {
	var sawModified, sawIntermediateNS bool

	for _, o := range r.Observations {
		modified := o.Mods != "" && o.Mods != "none"
		if modified {
			sawModified = true
			continue
		}
		// Unmodified name. NS is the RFC 7816 §2 default minimisation type and
		// something the page never requests, so it is attributable to the
		// resolver's walk. A/AAAA/TXT here are the page's own bare-token queries
		// and prove nothing either way.
		if o.Qtype == "NS" {
			sawIntermediateNS = true
		}
	}

	switch {
	case sawIntermediateNS:
		// Positive evidence stands on its own: the NS query happened, whatever
		// else did or did not.
		return QMinObserved
	case !sawModified:
		// Nothing to minimise through. Not a negative result.
		return QMinUnknown
	default:
		return QMinAbsent
	}
}
