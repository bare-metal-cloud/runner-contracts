package contracts

import "strings"

// AllowlistMatches reports whether host is permitted by the egress
// allowlist. Matching is hostname-suffix based: a host matches an entry
// when it equals the entry or is a subdomain of it (the entry followed
// by a dot). Registry CDNs serve blobs from sibling hosts, so suffix
// matching is the law of record. A whole-label boundary is respected:
// "evilregistry.acme.example" does NOT match "registry.acme.example".
//
// An empty (or nil) allowlist matches nothing: an empty list is legal
// and means deny-all.
//
// The entries are validated lowercase; the host is compared
// case-insensitively (DNS names are case-insensitive).
func AllowlistMatches(entries []string, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	for _, entry := range entries {
		entry = strings.ToLower(strings.TrimSuffix(entry, "."))
		if entry == "" {
			continue
		}
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}
