// Optional source-network filtering for normalized log streams. A filter is
// parsed once from the --source-cidr option value and then applied to the
// fully normalized source_ip of every successful event; per-line failures
// are never filtered out.
package relayproof

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// SourceCIDR is one parsed IPv4 source network expressed as an address plus
// a 0-32 prefix length. The address's host bits are discarded at parse time,
// so 192.0.2.123/24 and 192.0.2.0/24 are the same filter. A zero-value
// SourceCIDR is not a usable filter; obtain one through ParseSourceCIDR.
type SourceCIDR struct {
	network uint32 // network address after masking
	mask    uint32 // leading-prefix mask
	prefix  int    // canonical prefix length, used by String
}

// ParseSourceCIDR parses one --source-cidr value: a dotted-decimal IPv4
// address, a single slash, and a prefix length of 0-32. The grammar is
// deliberately narrower than net.ParseCIDR's:
//
//   - IPv6 networks (including ::ffff:192.0.2.0/120) are rejected outright;
//     the option always names an IPv4 range.
//   - The address must be exactly four decimal octets 0-255 with no leading
//     zeros, hex/octet forms, or abbreviated segments; the legacy alternative
//     bases the resolver libraries accept must not silently change a range.
//   - The prefix is a canonical decimal integer 0-32 with no sign or leading
//     zeros.
//
// Host bits in the address are ignored (192.0.2.123/24 denotes 192.0.2.0/24);
// a /32 matches exactly one address and /0 matches every IPv4 source.
func ParseSourceCIDR(text string) (*SourceCIDR, error) {
	addrText, prefixText, err := splitCIDRText(text)
	if err != nil {
		return nil, err
	}
	addr, err := parseDottedIPv4(addrText)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv4 CIDR %q: %v", text, err)
	}
	prefix, err := parsePrefixLength(prefixText)
	if err != nil {
		return nil, fmt.Errorf("invalid IPv4 CIDR %q: %v", text, err)
	}
	var mask uint32
	if prefix > 0 {
		mask = ^uint32(0) << (32 - prefix)
	}
	return &SourceCIDR{
		network: binary.BigEndian.Uint32(addr) & mask,
		mask:    mask,
		prefix:  prefix,
	}, nil
}

// splitCIDRText splits on the single required slash and rejects an empty
// address or prefix (covering the missing-value and trailing-slash cases).
func splitCIDRText(text string) (addr, prefix string, err error) {
	slash := strings.IndexByte(text, '/')
	if slash < 0 {
		return "", "", fmt.Errorf("expected ADDRESS/PREFIX with an IPv4 address and a slash (e.g. 192.0.2.0/24)")
	}
	if strings.IndexByte(text[slash+1:], '/') >= 0 {
		return "", "", fmt.Errorf("expected exactly one slash before the prefix length")
	}
	addr = text[:slash]
	prefix = text[slash+1:]
	if addr == "" || prefix == "" {
		return "", "", fmt.Errorf("expected ADDRESS/PREFIX with an IPv4 address and a prefix length (e.g. 192.0.2.0/24)")
	}
	return addr, prefix, nil
}

// parseDottedIPv4 accepts exactly four canonical decimal octets. It is
// hand-written rather than delegating to net.ParseIP so the accepted grammar
// is stated here once (no leading zeros, no alternate number bases), matching
// the strict input grammar used for the other fields.
func parseDottedIPv4(text string) (net.IP, error) {
	parts := strings.Split(text, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("address %q must be four dot-separated decimal octets", text)
	}
	addr := make(net.IP, 4)
	for i, part := range parts {
		if !isDecimalOctet(part) {
			return nil, fmt.Errorf("address %q must use decimal octets 0-255 with no leading zeros", text)
		}
		n, convErr := strconv.Atoi(part) // isDecimalOctet bounds the digits
		if convErr != nil || n > 255 {
			return nil, fmt.Errorf("address %q must use decimal octets 0-255 with no leading zeros", text)
		}
		addr[i] = byte(n)
	}
	return addr, nil
}

// isDecimalOctet accepts one to three ASCII digits spelling a canonical
// unsigned integer: "0" is allowed, but "00" and "01" are not.
func isDecimalOctet(s string) bool {
	if s == "" || len(s) > 3 {
		return false
	}
	if len(s) > 1 && s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parsePrefixLength accepts the canonical decimal spelling of 0 through 32.
func parsePrefixLength(s string) (int, error) {
	if s == "" || len(s) > 2 {
		return 0, fmt.Errorf("prefix length must be 0-32")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("prefix length must be 0-32 without leading zeros")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("prefix length must be 0-32")
		}
	}
	n, convErr := strconv.Atoi(s)
	if convErr != nil || n > 32 {
		return 0, fmt.Errorf("prefix length must be 0-32")
	}
	return n, nil
}

// String renders the canonical network the filter denotes, with host bits
// removed: ParseSourceCIDR("192.0.2.123/24").String() == "192.0.2.0/24".
func (f *SourceCIDR) String() string {
	return fmt.Sprintf("%d.%d.%d.%d/%d",
		byte(f.network>>24), byte(f.network>>16), byte(f.network>>8), byte(f.network), f.prefix)
}

// Contains reports whether ip falls in the IPv4 network. IPv4-mapped IPv6
// addresses (::ffff:192.0.2.1) denote the same IPv4 source and match; other
// IPv6 addresses (including the IPv4-compatible ::192.0.2.1) never match.
func (f *SourceCIDR) Contains(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	return binary.BigEndian.Uint32(v4)&f.mask == f.network
}

// MatchesEvent reports whether a normalized event's canonical source_ip is
// an IPv4 address inside the network. An event without a source address, or
// one whose source stayed IPv6, does not match and is filtered out — without
// being counted as a failure.
func (f *SourceCIDR) MatchesEvent(event *NormalizedEvent) bool {
	if event == nil || event.SourceIP == "" {
		return false
	}
	ip := net.ParseIP(event.SourceIP)
	return ip != nil && f.Contains(ip)
}
