// Command relayproof is the 跨链消息与轻客户端验证服务 entry point.
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

// sourceCIDRFlag is the sole normalize option: an IPv4 or IPv6 network
// that restricts which successful events are emitted.
const sourceCIDRFlag = "--source-cidr"

func main() {
	command := "demo"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	switch command {
	case "demo":
		runDemo()
	case "normalize":
		runNormalize()
	case "version":
		fmt.Println("relayproof 0.1.0")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: relayproof [demo|normalize|version|help]")
	fmt.Println()
	fmt.Println("  demo       run the built-in verification demo (default with no arguments)")
	fmt.Println("  normalize   read newline-delimited JSON logs from stdin and write")
	fmt.Println("              normalized event results to stdout, one JSON object per line;")
	fmt.Println("              exits non-zero when one or more input lines fail")
	fmt.Println()
	fmt.Println("              options:")
	fmt.Println("                --source-cidr <IP>/<prefix>")
	fmt.Println("                    emit a successful event only when its normalized")
	fmt.Println("                    source_ip lies in this single network; the network")
	fmt.Println("                    matches only its own address family. Supports an")
	fmt.Println(`                    IPv4 network "192.0.2.0/24" (prefix length 0-32) and`)
	fmt.Println(`                    an IPv6 network "2001:db8::/64" (prefix length 0-128,`)
	fmt.Println(`                    compressed or full spelling, e.g. "2001:db8::1234/64"`)
	fmt.Println(`                    selects the same range as "2001:db8::/64"; "/128" and`)
	fmt.Println(`                    "::/0" match one address and every IPv6 source). An`)
	fmt.Println("                    IPv4-mapped IPv6 argument is rejected; spell that")
	fmt.Println("                    network as IPv4. Failed lines are still reported.")
	fmt.Println("                    May be given once.")
	fmt.Println("  version     print the relayproof version")
	fmt.Println("  help        show this help")
}

func runNormalize() {
	// Options are parsed before stdin is read: a malformed option exits 2
	// with empty stdout, exactly like a stream-level failure, and no log
	// content is consumed or produced for it.
	filter, err := parseNormalizeOptions(os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "normalize: %v\n", err)
		os.Exit(2)
	}
	failures, err := relayproof.NormalizeReaderFiltered(os.Stdin, os.Stdout, filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "normalize: %v\n", err)
		os.Exit(2)
	}
	if failures > 0 {
		os.Exit(1)
	}
}

// parseNormalizeOptions accepts at most one --source-cidr option, in either
// "--source-cidr value" or "--source-cidr=value" form. A missing or empty
// value, a value outside the IPv4/IPv6 network grammar (including an
// IPv4-mapped IPv6 argument), a repeated option, or any other argument is a
// parameter error: the caller reports it on stderr and exits 2 before
// opening the log stream.
func parseNormalizeOptions(args []string) (*relayproof.SourceCIDRFilter, error) {
	var filter *relayproof.SourceCIDRFilter
	specified := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == sourceCIDRFlag:
			if specified {
				return nil, fmt.Errorf("%s may be specified at most once", sourceCIDRFlag)
			}
			if i+1 >= len(args) {
				return nil, fmt.Errorf("%s requires a value: an IPv4 network with a \"/0\" to \"/32\" prefix length (e.g. %q) or an IPv6 network with a \"/0\" to \"/128\" prefix length (e.g. %q)",
					sourceCIDRFlag, "192.0.2.0/24", "2001:db8::/64")
			}
			i++
			value := args[i]
			parsed, err := relayproof.ParseSourceCIDRFilter(value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s value: %w", sourceCIDRFlag, err)
			}
			filter, specified = &parsed, true
		case strings.HasPrefix(arg, sourceCIDRFlag+"="):
			if specified {
				return nil, fmt.Errorf("%s may be specified at most once", sourceCIDRFlag)
			}
			value := strings.TrimPrefix(arg, sourceCIDRFlag+"=")
			parsed, err := relayproof.ParseSourceCIDRFilter(value)
			if err != nil {
				return nil, fmt.Errorf("invalid %s value: %w", sourceCIDRFlag, err)
			}
			filter, specified = &parsed, true
		default:
			return nil, fmt.Errorf("unknown argument %q; normalize accepts only %s <IPv4 or IPv6 network>/<prefix>", arg, sourceCIDRFlag)
		}
	}
	return filter, nil
}

func runDemo() {
	headers := map[string]relayproof.Header{
		"chain-a": {Chain: "chain-a", Height: 1024, Root: "0xabc", Trusted: true},
	}
	consumed := map[string]bool{}
	messages := []relayproof.Message{
		{ID: "msg-1", From: "chain-a", To: "chain-b", Nonce: 7, ProofAt: 1000},
		{ID: "msg-2", From: "chain-c", To: "chain-b", Nonce: 1, ProofAt: 10},
	}
	for _, message := range messages {
		delivery := relayproof.Verify(headers, message, consumed)
		fmt.Printf("message=%s status=%s reason=%s\n", delivery.Message, delivery.Status, delivery.Reason)
	}
	replay := relayproof.Verify(headers, messages[0], consumed)
	fmt.Printf("replay of %s status=%s reason=%s\n", replay.Message, replay.Status, replay.Reason)
	fmt.Println("pending:", relayproof.Pending(headers, messages))
}
