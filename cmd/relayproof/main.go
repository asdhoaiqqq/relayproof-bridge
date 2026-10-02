// Command relayproof is the 跨链消息与轻客户端验证服务 entry point.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
	case "version":
		fmt.Println("relayproof 0.1.0")
	case "normalize":
		runNormalize()
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println("usage: relayproof [demo|version|normalize|help]")
	fmt.Println("  normalize  read JSON log events from stdin and write normalized JSON per line to stdout")
}

func runNormalize() {
	failed, err := normalizeStream(os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if failed {
		os.Exit(1)
	}
}

// normalizeStream reads JSON log lines from r and writes one normalized JSON
// result per input line to w. Blank lines produce no output but still count
// as physical lines. It reports whether any line failed.
func normalizeStream(r io.Reader, w io.Writer) (bool, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(w)
	lineNo := 0
	failed := false
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		result := relayproof.NormalizeLine(line, lineNo)
		if !result.OK {
			failed = true
		}
		if err := enc.Encode(result); err != nil {
			return failed, fmt.Errorf("write error: %v", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return failed, fmt.Errorf("read error: %v", err)
	}
	return failed, nil
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
