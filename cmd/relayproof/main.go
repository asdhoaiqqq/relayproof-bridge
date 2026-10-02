// Command relayproof is the 跨链消息与轻客户端验证服务 entry point.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

func main() {
	if len(os.Args) < 2 {
		runDemo()
		return
	}
	switch os.Args[1] {
	case "demo":
		runDemo()
	case "version":
		fmt.Println("relayproof 0.2.0")
	case "queue":
		runQueue(os.Args[2:])
	case "verify":
		if err := runVerify(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`usage: relayproof <command> [flags]

commands:
  demo                         run the in-memory verification demo
  version                      print version
  queue                        manage the durable local message queue
  verify [--state DIR]         run the deterministic end-to-end verification
  help                         show this help

queue subcommands (all take --state DIR):
  register-source --chain C
  header --chain C --height N --root R [--trusted]
  submit --id ID --from C --to C --nonce N --proof-at H --payload P [--expires-at MS]
  advance --now MS
  query [--id ID]

times are Unix milliseconds; --expires-at 0 (default) means never expire.`)
}

func runQueue(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "queue requires a subcommand: register-source|header|submit|advance|query")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	var err error
	switch sub {
	case "register-source":
		err = queueCmdRegisterSource(rest)
	case "header":
		err = queueCmdHeader(rest)
	case "submit":
		err = queueCmdSubmit(rest)
	case "advance":
		err = queueCmdAdvance(rest)
	case "query":
		err = queueCmdQuery(rest)
	default:
		fmt.Fprintf(os.Stderr, "unknown queue subcommand %q\n", sub)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitCode(err))
	}
}

func exitCode(err error) int {
	switch {
	case errors.Is(err, relayproof.ErrLocked):
		return 11
	case errors.Is(err, relayproof.ErrCorrupt):
		return 12
	case errors.Is(err, relayproof.ErrConflict):
		return 13
	case errors.Is(err, relayproof.ErrHeaderConflict):
		return 16
	case errors.Is(err, relayproof.ErrTerminal):
		return 14
	case errors.Is(err, relayproof.ErrInvalidArg):
		return 2
	case errors.Is(err, relayproof.ErrStorage):
		return 15
	default:
		return 1
	}
}

type globalFlags struct {
	state string
}

func newQueueFlagSet(name string, g *globalFlags) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&g.state, "state", "", "state directory (required)")
	return fs
}

func (g *globalFlags) mustState() {
	if g.state == "" {
		fmt.Fprintln(os.Stderr, "error: --state is required")
		os.Exit(2)
	}
}

func queueCmdRegisterSource(rest []string) error {
	g := &globalFlags{}
	fs := newQueueFlagSet("register-source", g)
	chain := fs.String("chain", "", "source chain name (required)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *chain == "" {
		return fmt.Errorf("%w: --chain is required", relayproof.ErrInvalidArg)
	}
	g.mustState()
	q, err := relayproof.Open(g.state)
	if err != nil {
		return err
	}
	defer q.Close()
	if err := q.RegisterSource(*chain); err != nil {
		return err
	}
	fmt.Printf("registered source chain %s\n", *chain)
	return nil
}

func queueCmdHeader(rest []string) error {
	g := &globalFlags{}
	fs := newQueueFlagSet("header", g)
	chain := fs.String("chain", "", "chain name (required)")
	height := fs.Int64("height", -1, "header height (required)")
	root := fs.String("root", "", "header commitment root")
	trusted := fs.Bool("trusted", false, "mark the header as trusted")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *chain == "" || *height < 0 {
		return fmt.Errorf("%w: --chain and non-negative --height are required", relayproof.ErrInvalidArg)
	}
	g.mustState()
	q, err := relayproof.Open(g.state)
	if err != nil {
		return err
	}
	defer q.Close()
	h := relayproof.Header{Chain: *chain, Height: *height, Root: *root, Trusted: *trusted}
	if err := q.UpsertHeader(h); err != nil {
		return err
	}
	fmt.Printf("stored header chain=%s height=%d trusted=%t\n", *chain, *height, *trusted)
	return nil
}

func queueCmdSubmit(rest []string) error {
	g := &globalFlags{}
	fs := newQueueFlagSet("submit", g)
	id := fs.String("id", "", "message id (required)")
	from := fs.String("from", "", "source chain (required)")
	to := fs.String("to", "", "destination chain (required)")
	nonce := fs.Uint64("nonce", 0, "message nonce on the source chain")
	payload := fs.String("payload", "", "message payload")
	proofAt := fs.Int64("proof-at", -1, "height at which the message is proven (required)")
	expiresAt := fs.Int64("expires-at", 0, "absolute expiry as Unix ms; 0 means never")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *id == "" || *from == "" || *to == "" || *proofAt < 0 {
		return fmt.Errorf("%w: --id, --from, --to and non-negative --proof-at are required", relayproof.ErrInvalidArg)
	}
	g.mustState()
	q, err := relayproof.Open(g.state)
	if err != nil {
		return err
	}
	defer q.Close()
	rec, err := q.Submit(relayproof.Envelope{
		Message: relayproof.Message{
			ID: *id, From: *from, To: *to, Nonce: *nonce,
			Payload: *payload, ProofAt: *proofAt,
		},
		ExpiresAt: *expiresAt,
	})
	if err != nil {
		return err
	}
	return emitJSON(recordJSON(rec))
}

func queueCmdAdvance(rest []string) error {
	g := &globalFlags{}
	fs := newQueueFlagSet("advance", g)
	now := fs.Int64("now", -1, "processing time as Unix milliseconds (required)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *now < 0 {
		return fmt.Errorf("%w: non-negative --now is required", relayproof.ErrInvalidArg)
	}
	g.mustState()
	q, err := relayproof.Open(g.state)
	if err != nil {
		return err
	}
	defer q.Close()
	report, err := q.Advance(*now)
	if err != nil {
		return err
	}
	return emitJSON(advanceJSON(report))
}

func queueCmdQuery(rest []string) error {
	g := &globalFlags{}
	fs := newQueueFlagSet("query", g)
	id := fs.String("id", "", "message id; omit to list all records in submission order")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	g.mustState()
	q, err := relayproof.Open(g.state)
	if err != nil {
		return err
	}
	defer q.Close()
	if *id != "" {
		rec, ok := q.Query(*id)
		if !ok {
			return fmt.Errorf("no record for message %q", *id)
		}
		return emitJSON(queryJSON(rec))
	}
	for _, rec := range q.Queries() {
		if err := emitJSON(queryJSON(rec)); err != nil {
			return err
		}
	}
	return nil
}

type jsonRecord struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Attempts  int    `json:"attempts"`
	NextRetry int64  `json:"nextRetryMs,omitempty"`
	ExpiresAt int64  `json:"expiresAtMs,omitempty"`
}

func recordJSON(r *relayproof.Record) jsonRecord {
	return jsonRecord{
		ID: r.Msg.Message.ID, Status: r.Status, Reason: r.Reason,
		Attempts: r.Attempts, NextRetry: r.NextRetry, ExpiresAt: r.Msg.ExpiresAt,
	}
}

type jsonQuery struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	To        string `json:"to"`
	Nonce     uint64 `json:"nonce"`
	Payload   string `json:"payload"`
	ProofAt   int64  `json:"proofAtHeight"`
	ExpiresAt int64  `json:"expiresAtMs,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Attempts  int    `json:"attempts"`
	NextRetry int64  `json:"nextRetryMs,omitempty"`
}

func queryJSON(q relayproof.Query) jsonQuery {
	return jsonQuery{
		ID: q.ID, From: q.From, To: q.To, Nonce: q.Nonce, Payload: q.Payload,
		ProofAt: q.ProofAt, ExpiresAt: q.ExpiresAt, Status: q.Status,
		Reason: q.Reason, Attempts: q.Attempts, NextRetry: q.NextRetry,
	}
}

type jsonAdvance struct {
	NowMs   int64               `json:"nowMs"`
	Results []relayproof.Result `json:"results"`
}

func advanceJSON(r *relayproof.AdvanceReport) jsonAdvance {
	return jsonAdvance{NowMs: r.Now, Results: r.Results}
}

func emitJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode output: %w", err)
	}
	return nil
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
