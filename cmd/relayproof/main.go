// Command relayproof is the 跨链消息与轻客户端验证服务 entry point.
package main

import (
	"fmt"
	"os"

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
	fmt.Println("  version     print the relayproof version")
	fmt.Println("  help        show this help")
}

func runNormalize() {
	failures, err := relayproof.NormalizeReader(os.Stdin, os.Stdout)
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
