// Command relayproof is the 跨链消息与轻客户端验证服务 entry point.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

func main() {
	command := "demo"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}
	var err error
	switch command {
	case "demo":
		runDemo()
	case "version":
		fmt.Println("relayproof 0.2.0")
	case "submit":
		err = runSubmit(os.Args[2:])
	case "header":
		err = runHeader(os.Args[2:])
	case "advance":
		err = runAdvance(os.Args[2:])
	case "query":
		err = runQuery(os.Args[2:])
	case "list":
		err = runList(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("usage: relayproof <command> [flags]")
	fmt.Println()
	fmt.Println("commands:")
	fmt.Println("  demo                              run the built-in verification demo")
	fmt.Println("  version                           print version")
	fmt.Println("  submit   --dir DIR --id ID --from CHAIN --to CHAIN --nonce N --proof-at H --expire-at T [--payload P]")
	fmt.Println("  header   --dir DIR --chain CHAIN --height H [--root R] [--trusted]")
	fmt.Println("  advance  --dir DIR --time T       advance processing time (Unix ms)")
	fmt.Println("  query    --dir DIR --id ID        print one record as JSON")
	fmt.Println("  list     --dir DIR                print all records as JSON")
	fmt.Println("  help                              show this help")
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func runSubmit(args []string) error {
	fs := newFlagSet("submit")
	dir := fs.String("dir", "", "state directory")
	id := fs.String("id", "", "message id")
	from := fs.String("from", "", "source chain")
	to := fs.String("to", "", "destination chain")
	nonce := fs.Uint64("nonce", 0, "nonce")
	payload := fs.String("payload", "", "payload")
	proofAt := fs.Int64("proof-at", 0, "proof height")
	expireAt := fs.Int64("expire-at", 0, "absolute expiry (unix ms)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *id == "" || *from == "" || *to == "" {
		return fmt.Errorf("submit requires --dir, --id, --from and --to")
	}
	if *proofAt <= 0 || *expireAt <= 0 {
		return fmt.Errorf("submit requires --proof-at and --expire-at (positive unix ms)")
	}
	store, err := relayproof.Open(*dir)
	if err != nil {
		return err
	}
	defer store.Close()
	m := relayproof.Message{
		ID:       *id,
		From:     *from,
		To:       *to,
		Nonce:    *nonce,
		Payload:  *payload,
		ProofAt:  *proofAt,
		ExpireAt: *expireAt,
	}
	r, err := store.Submit(m)
	if err != nil {
		return err
	}
	return printJSON(r)
}

func runHeader(args []string) error {
	fs := newFlagSet("header")
	dir := fs.String("dir", "", "state directory")
	chain := fs.String("chain", "", "source chain")
	height := fs.Int64("height", 0, "header height")
	root := fs.String("root", "", "header root")
	trusted := fs.Bool("trusted", false, "header is trusted")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *chain == "" {
		return fmt.Errorf("header requires --dir and --chain")
	}
	store, err := relayproof.Open(*dir)
	if err != nil {
		return err
	}
	defer store.Close()
	h := relayproof.Header{Chain: *chain, Height: *height, Root: *root, Trusted: *trusted}
	if err := store.SetHeader(h); err != nil {
		return err
	}
	return printJSON(h)
}

func runAdvance(args []string) error {
	fs := newFlagSet("advance")
	dir := fs.String("dir", "", "state directory")
	t := fs.Int64("time", 0, "processing time (unix ms)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("advance requires --dir")
	}
	store, err := relayproof.Open(*dir)
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Advance(*t); err != nil {
		return err
	}
	now, _ := store.Time()
	return printJSON(map[string]int64{"advanced_to": now})
}

func runQuery(args []string) error {
	fs := newFlagSet("query")
	dir := fs.String("dir", "", "state directory")
	id := fs.String("id", "", "message id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || *id == "" {
		return fmt.Errorf("query requires --dir and --id")
	}
	store, err := relayproof.Open(*dir)
	if err != nil {
		return err
	}
	defer store.Close()
	r, err := store.Query(*id)
	if err != nil {
		return err
	}
	return printJSON(r)
}

func runList(args []string) error {
	fs := newFlagSet("list")
	dir := fs.String("dir", "", "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("list requires --dir")
	}
	store, err := relayproof.Open(*dir)
	if err != nil {
		return err
	}
	defer store.Close()
	return printJSON(store.List())
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func runDemo() {
	headers := map[string]relayproof.Header{
		"chain-a": {Chain: "chain-a", Height: 1024, Root: "0xabc", Trusted: true},
	}
	consumed := map[string]bool{}
	messages := []relayproof.Message{
		{ID: "msg-1", From: "chain-a", To: "chain-b", Nonce: 7, ProofAt: 1000, ExpireAt: 1_000_000},
		{ID: "msg-2", From: "chain-c", To: "chain-b", Nonce: 1, ProofAt: 10, ExpireAt: 2_000_000},
	}
	for _, message := range messages {
		delivery := relayproof.Verify(headers, message, consumed)
		fmt.Printf("message=%s status=%s reason=%s\n", delivery.Message, delivery.Status, delivery.Reason)
	}
	replay := relayproof.Verify(headers, messages[0], consumed)
	fmt.Printf("replay of %s status=%s reason=%s\n", replay.Message, replay.Status, replay.Reason)
	fmt.Println("pending:", relayproof.Pending(headers, messages))
}
