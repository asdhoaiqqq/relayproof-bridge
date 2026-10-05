// Command relayproof is the 跨链消息与轻客户端验证服务 entry point.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

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
	fmt.Println("  normalize options:")
	fmt.Println("    --source-cidr=IPV4/PREFIX")
	fmt.Println("              emit successful events only when their normalized source_ip")
	fmt.Println("              is inside one IPv4 network (dotted-decimal address plus a")
	fmt.Println("              0-32 prefix length, e.g. 192.0.2.0/24); host bits are")
	fmt.Println("              ignored, /32 matches one address and /0 every IPv4 source.")
	fmt.Println("              May be given at most once; failed log lines are still emitted.")
	fmt.Println("  version     print the relayproof version")
	fmt.Println("  help        show this help")
}

// normalizeConfig holds the parsed normalize subcommand arguments.
type normalizeConfig struct {
	sourceCIDR string // raw --source-cidr value; set when the flag was given
}

// parseNormalizeArgs parses the arguments after "normalize". Only
// --source-cidr is accepted, at most once, and always with a non-empty
// value; both "--source-cidr VALUE" and "--source-cidr=VALUE" spellings
// work (a single leading dash is accepted too, like the standard flag
// package). A bare "--" is not an option: normalizing never takes positional
// file arguments, so it is reported like any other unknown argument. Any
// problem is a usage error that must end the process with status 2 before
// any log is read.
func parseNormalizeArgs(args []string) (normalizeConfig, error) {
	var cfg normalizeConfig
	sourceCIDRSet := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name := arg
		inlineValue := ""
		hasInline := false
		switch {
		case strings.HasPrefix(arg, "--source-cidr"):
			name = "--source-cidr"
		case strings.HasPrefix(arg, "-source-cidr"):
			name = "-source-cidr"
		default:
			return cfg, fmt.Errorf("unknown normalize argument %q", arg)
		}
		if rest := arg[len(name):]; strings.HasPrefix(rest, "=") {
			inlineValue = rest[1:]
			hasInline = true
		} else if rest != "" {
			return cfg, fmt.Errorf("unknown normalize argument %q", arg)
		}

		var value string
		switch {
		case hasInline:
			value = inlineValue
		case i+1 < len(args) && !strings.HasPrefix(args[i+1], "-"):
			i++
			value = args[i]
		default:
			return cfg, errors.New(`--source-cidr requires a value: use --source-cidr IPV4/PREFIX or --source-cidr=IPV4/PREFIX`)
		}
		if value == "" {
			return cfg, errors.New(`--source-cidr requires a non-empty value: dotted-decimal IPv4 address plus a /0-/32 prefix`)
		}
		if sourceCIDRSet {
			return cfg, errors.New("--source-cidr may be specified only once")
		}
		cfg.sourceCIDR = value
		sourceCIDRSet = true
	}
	return cfg, nil
}

func runNormalize() {
	cfg, err := parseNormalizeArgs(os.Args[2:])
	if err != nil {
		// Argument problems are reported before the log stream is opened:
		// nothing is read from stdin and stdout stays empty.
		fmt.Fprintf(os.Stderr, "normalize: %v\n", err)
		fmt.Fprintln(os.Stderr, "usage: relayproof normalize [--source-cidr=IPV4/PREFIX]")
		os.Exit(2)
	}

	opts := relayproof.NormalizeOptions{}
	if cfg.sourceCIDR != "" {
		filter, err := relayproof.ParseSourceCIDR(cfg.sourceCIDR)
		if err != nil {
			fmt.Fprintf(os.Stderr, "normalize: %v\n", err)
			fmt.Fprintln(os.Stderr, "usage: relayproof normalize [--source-cidr=IPV4/PREFIX]")
			os.Exit(2)
		}
		opts.SourceFilter = filter
	}

	failures, err := relayproof.NormalizeReaderOptions(os.Stdin, os.Stdout, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "normalize: %v\n", err)
		os.Exit(2)
	}
	if failures > 0 {
		os.Exit(1)
	}
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
