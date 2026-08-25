package qualityoauth

import (
	"sort"
	"strings"
)

// splitScopes parses an OAuth space-delimited scope string. Commas are
// tolerated because they show up in hand-written config.
func splitScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == ','
	})
	return dedupeScopes(fields)
}

// dedupeScopes returns the scopes deduplicated and sorted, so a stored scope
// set compares equal regardless of the order the server listed it in.
func dedupeScopes(scopes []string) []string {
	if len(scopes) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	if len(out) == 0 {
		// nil, not an empty slice: "no scopes recorded" is what distinguishes a
		// legacy-migrated credential from one that genuinely granted nothing.
		return nil
	}
	sort.Strings(out)
	return out
}

// ScopesCover reports whether granted includes every scope in needed.
func ScopesCover(granted, needed []string) bool {
	return len(MissingScopes(granted, needed)) == 0
}

// MissingScopes returns the scopes in needed that granted does not carry.
func MissingScopes(granted, needed []string) []string {
	if len(needed) == 0 {
		return nil
	}
	have := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		have[s] = struct{}{}
	}
	var missing []string
	for _, s := range dedupeScopes(needed) {
		if _, ok := have[s]; !ok {
			missing = append(missing, s)
		}
	}
	return missing
}

// ConsentedScopes returns the scopes a stored token may contribute to the next
// login's request, which is only the ones a consent screen actually granted.
//
// Scopes recovered from a token's own claims are deliberately excluded. A
// credential adopted from the pre-consolidation store has them, and for those
// the claim lists the caller's entire role-derived envelope: the old flow sent
// no `scope` parameter, so the server had nothing to narrow to. Unioning that in
// would put 40-odd permissions on every future consent screen and keep them
// there forever — the opposite of what asking for a scope set is for. Dropping
// them costs one broadening round-trip per tool, after which every login unions
// a set that some human really did approve.
func (t *Token) ConsentedScopes() []string {
	if t == nil || t.ScopeSource != ScopeSourceConsent {
		return nil
	}
	return t.Scopes
}

// UnionScopes merges scope sets. It is what makes incremental consent work:
// when the shared token is missing a scope a tool needs, the next login asks
// for granted ∪ needed rather than replacing one narrow grant with another.
func UnionScopes(sets ...[]string) []string {
	var all []string
	for _, set := range sets {
		all = append(all, set...)
	}
	return dedupeScopes(all)
}
