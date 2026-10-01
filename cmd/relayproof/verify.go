package main

import (
	"fmt"
	"os"

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
