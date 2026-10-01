package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/asdhoaiqqq/relayproof-bridge/relayproof"
)

// runVerify drives a deterministic scenario in a temporary (or --state given)
// directory so every terminal state, waiting, expiry, replay, restart and
// locking behaviour can be observed offline.
func runVerify(args []string) error {
	stateDir := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--state":
			if i+1 >= len(args) {
				return fmt.Errorf("--state requires a directory")
			}
			stateDir = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown verify flag %q", args[i])
		}
	}
	if stateDir == "" {
		var err error
		stateDir, err = os.MkdirTemp("", "relayproof-verify-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stateDir)
	}
	fmt.Println("verify state dir:", stateDir)

	verifyAmbiguousPaths()

	must := func(step string, err error) {
		if err != nil {
			panic(step + ": " + err.Error())
		}
	}

	q, err := relayproof.Open(stateDir)
	must("open", err)

	must("register a", q.RegisterSource("chain-a"))
	must("header a@80 untrusted", q.UpsertHeader(relayproof.Header{Chain: "chain-a", Height: 80, Root: "0x80"}))

	// Two messages share one nonce combination; one will win, one replay.
	_, err = q.Submit(relayproof.Envelope{Message: relayproof.Message{ID: "m-win", From: "chain-a", To: "chain-b", Nonce: 7, ProofAt: 100}})
	must("submit m-win", err)
	_, err = q.Submit(relayproof.Envelope{Message: relayproof.Message{ID: "m-lose", From: "chain-a", To: "chain-b", Nonce: 7, ProofAt: 100}})
	must("submit m-lose", err)
	// Expiring message (proof height beyond the 100 header, so it waits until
	// its 5000 expiry) and an unknown-source message.
	_, err = q.Submit(relayproof.Envelope{
		Message:   relayproof.Message{ID: "m-exp", From: "chain-a", To: "chain-b", Nonce: 8, ProofAt: 1000},
		ExpiresAt: 5000,
	})
	must("submit m-exp", err)
	_, err = q.Submit(relayproof.Envelope{Message: relayproof.Message{ID: "m-alien", From: "chain-x", To: "chain-b", Nonce: 1, ProofAt: 1}})
	must("submit m-alien", err)

	step := func(label string, now int64) {
		rep, err := q.Advance(now)
		must(label, err)
		fmt.Printf("advance %d -> %d result(s)\n", rep.Now, len(rep.Results))
		for _, r := range rep.Results {
			fmt.Printf("    %-8s %-14s %s\n", r.ID, r.Status, r.Reason)
		}
	}

	step("t=1000 header short", 1000) // win/lose/exp waiting; alien unknown-source
	must("header a@100 trusted", q.UpsertHeader(relayproof.Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true}))
	// Header does not bypass the 1s retry: win/lose stay waiting until 2000.
	step("t=1500 retry not due", 1500)
	step("t=2000 retry due, win delivers", 2000) // win success, lose replay
	step("t=5000 expiry instant", 5000)          // m-exp expired exactly at boundary

	printRecords(q)
	must("close before reopen", q.Close())

	// Restart: delivered message must not deliver again, state fully restored.
	q2, err := relayproof.Open(stateDir)
	must("reopen", err)
	rep, err := q2.Advance(9000)
	must("advance after reopen", err)
	if len(rep.Results) != 0 {
		return fmt.Errorf("terminal messages processed again after restart: %+v", rep.Results)
	}
	fmt.Println("restart at 9000: 0 results, last advanced time =", q2.Now())

	// Second concurrent opener must be refused; directory reusable after close.
	if _, err := relayproof.Open(stateDir); err == nil {
		return fmt.Errorf("concurrent open unexpectedly succeeded")
	} else {
		fmt.Println("concurrent open refused:", err)
	}
	must("final close", q2.Close())
	q3, err := relayproof.Open(stateDir)
	if err != nil {
		return fmt.Errorf("directory not reusable after holder exit: %w", err)
	}
	fmt.Println("directory reusable after holder closed")
	if err := q3.Close(); err != nil {
		return err
	}
	fmt.Println("verify: OK")
	return nil
}

func printRecords(q *relayproof.Queue) {
	fmt.Println("records (submission order):")
	for _, r := range q.Queries() {
		retry := "-"
		if r.NextRetry != 0 {
			retry = fmt.Sprintf("%d", r.NextRetry)
		}
		fmt.Printf("    %-8s %-14s retry=%-6s %s\n", r.ID, r.Status, retry, r.Reason)
	}
}

// verifyAmbiguousPaths drives the replay-protection fix: two distinct routing
// paths that flatten to the same string under any delimiter-joined key must
// both deliver. The colon pair is expressible on the command line as well;
// the U+0000 pair can only be submitted through the Go API because argv
// strings cannot contain a NUL byte. A genuine same-path repeat must still
// be a replay whose reason names the real winner, and the consumption
// relationships must survive a close/reopen cycle.
func verifyAmbiguousPaths() {
	// --- In-memory Verify entry point. ---
	headers := map[string]relayproof.Header{
		"a:b": {Chain: "a:b", Height: 100, Trusted: true},
		"a":   {Chain: "a", Height: 100, Trusted: true},
	}
	consumed := map[string]bool{}
	msgs := []relayproof.Message{
		{ID: "mem-col-1", From: "a:b", To: "c", Nonce: 7, ProofAt: 10},
		{ID: "mem-col-2", From: "a", To: "b:c", Nonce: 7, ProofAt: 10},
		{ID: "mem-nul-1", From: "a\x00b", To: "c", Nonce: 7, ProofAt: 10},
		{ID: "mem-nul-2", From: "a", To: "b\x00c", Nonce: 7, ProofAt: 10},
	}
	fmt.Println("ambiguous-path check (in-memory Verify):")
	for _, m := range msgs {
		// The two NUL-bearing messages also need their own source header.
		headers[m.From] = relayproof.Header{Chain: m.From, Height: 100, Trusted: true}
		d := relayproof.Verify(headers, m, consumed)
		fmt.Printf("    %-10s %-10s %s\n", d.Message, d.Status, d.Reason)
		if d.Status != "delivered" {
			panic("distinct path " + m.ID + " was mistaken for a replay")
		}
	}
	d := relayproof.Verify(headers, msgs[0], consumed)
	if d.Status != "rejected" || !strings.Contains(d.Reason, "replay") {
		panic("genuine repeat of mem-col-1 was not a replay: " + d.Reason)
	}
	fmt.Printf("    %-10s %-10s %s\n", d.Message, d.Status, d.Reason)

	// --- Durable queue, including persistence across reopen. ---
	dir, err := os.MkdirTemp("", "relayproof-verify-paths-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	q, err := relayproof.Open(dir)
	if err != nil {
		panic(err)
	}
	for _, chain := range []string{"a:b", "a", "a\x00b"} {
		if err := q.RegisterSource(chain); err != nil {
			panic(err)
		}
		if err := q.UpsertHeader(relayproof.Header{Chain: chain, Height: 100, Trusted: true}); err != nil {
			panic(err)
		}
	}
	submit := func(id, from, to string) {
		_, err := q.Submit(relayproof.Envelope{
			Message: relayproof.Message{ID: id, From: from, To: to, Nonce: 7, ProofAt: 10},
		})
		if err != nil {
			panic(err)
		}
	}
	submit("q-col-1", "a:b", "c")
	submit("q-col-2", "a", "b:c")
	submit("q-nul-1", "a\x00b", "c")
	submit("q-dup", "a:b", "c") // genuinely the same triple as q-col-1

	rep, err := q.Advance(1000)
	if err != nil {
		panic(err)
	}
	fmt.Println("ambiguous-path check (durable queue):")
	want := map[string]string{
		"q-col-1": relayproof.StatusSuccess,
		"q-col-2": relayproof.StatusSuccess,
		"q-nul-1": relayproof.StatusSuccess,
		"q-dup":   relayproof.StatusReplay,
	}
	got := map[string]relayproof.Result{}
	for _, r := range rep.Results {
		got[r.ID] = r
		fmt.Printf("    %-10s %-14s %s\n", r.ID, r.Status, r.Reason)
	}
	for id, st := range want {
		r, ok := got[id]
		if !ok || r.Status != st {
			panic(fmt.Sprintf("%s: want %s got %+v", id, st, r))
		}
	}
	if !strings.Contains(got["q-dup"].Reason, "q-col-1") {
		panic("replay reason must name the real winner q-col-1: " + got["q-dup"].Reason)
	}
	if err := q.Close(); err != nil {
		panic(err)
	}

	q2, err := relayproof.Open(dir)
	if err != nil {
		panic(err)
	}
	defer q2.Close()
	rep, err = q2.Advance(2000)
	if err != nil {
		panic(err)
	}
	if len(rep.Results) != 0 {
		panic(fmt.Sprintf("historical successes processed again after reopen: %+v", rep.Results))
	}
	for id, st := range want {
		r, ok := q2.Query(id)
		if !ok || r.Status != st {
			panic(fmt.Sprintf("after reopen %s: want %s got %+v", id, st, r))
		}
		// Full chain names, including the NUL bytes, must survive intact.
		if id == "q-col-1" && (r.From != "a:b" || r.To != "c") {
			panic(fmt.Sprintf("%s names rewritten: %q -> %q", id, r.From, r.To))
		}
		if id == "q-nul-1" && (r.From != "a\x00b" || r.To != "c") {
			panic(fmt.Sprintf("%s names rewritten: %q -> %q", id, r.From, r.To))
		}
	}
	// New id on the path that shares the old NUL-flattened identifier with the
	// historical q-nul-1 ("a\x00b"->"c" and "a"->"b\x00c" used to collide).
	// It is a different triple, so it must deliver; reusing q-nul-1's exact
	// triple under any new id must still be a replay.
	if _, err := q2.Submit(relayproof.Envelope{
		Message: relayproof.Message{ID: "q-nul-1-again", From: "a\x00b", To: "c", Nonce: 7, ProofAt: 10},
	}); err != nil {
		panic(err)
	}
	if _, err := q2.Submit(relayproof.Envelope{
		Message: relayproof.Message{ID: "q-nul-2", From: "a", To: "b\x00c", Nonce: 7, ProofAt: 10},
	}); err != nil {
		panic(err)
	}
	if _, err := q2.Advance(3000); err != nil {
		panic(err)
	}
	if r, ok := q2.Query("q-nul-2"); !ok || r.Status != relayproof.StatusSuccess {
		panic(fmt.Sprintf("distinct path sharing old flattened key must deliver: %+v", r))
	}
	if r, ok := q2.Query("q-nul-1-again"); !ok || r.Status != relayproof.StatusReplay {
		panic(fmt.Sprintf("same triple under a new id must still replay: %+v", r))
	} else if !strings.Contains(r.Reason, "q-nul-1") {
		panic("replay reason must point at the actual success q-nul-1: " + r.Reason)
	}
	fmt.Println("ambiguous-path check: OK")
}
