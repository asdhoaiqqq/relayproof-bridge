package relayproof

import (
	"errors"
	"testing"
)

// These tests pin the queue-level identity rule behind the CLI regression
// tests: re-using a non-terminal message id is idempotent only when the ENTIRE
// envelope content is identical — source chain, destination chain, nonce,
// payload, proof height and absolute expiry. Identity is never judged by id
// alone or by the (source, destination, nonce) replay triple alone. A rejected
// resubmit must persist nothing, and the returned existing record must match
// what Query/Queries report.

func fullEnvelope(id string) Envelope {
	return Envelope{
		Message: Message{
			ID:      id,
			From:    "chain-a",
			To:      "chain-b",
			Nonce:   7,
			Payload: "hello",
			ProofAt: 90,
		},
		ExpiresAt: 9_000_000_000_000,
	}
}

// Changing any single content field of a pending id is ErrConflict; the
// original record keeps every field, its pending state and its submission
// position, nothing new is persisted, and an identical resubmit afterwards
// still returns the original.
func TestSubmitConflictForEverySingleContentField(t *testing.T) {
	base := fullEnvelope("m")
	cases := []struct {
		name   string
		mutate func(Envelope) Envelope
	}{
		{"source chain", func(e Envelope) Envelope { e.Message.From = "chain-other"; return e }},
		{"destination chain", func(e Envelope) Envelope { e.Message.To = "chain-c"; return e }},
		{"nonce", func(e Envelope) Envelope { e.Message.Nonce = 8; return e }},
		{"payload", func(e Envelope) Envelope { e.Message.Payload = "HELLO"; return e }},
		{"proof height", func(e Envelope) Envelope { e.Message.ProofAt = 91; return e }},
		{"absolute expiry", func(e Envelope) Envelope { e.ExpiresAt = 9_000_000_000_001; return e }},
		// Explicit zero values are real content too: turning the expiry off
		// after a finite expiry was stored must conflict.
		{"expiry to never", func(e Envelope) Envelope { e.ExpiresAt = 0; return e }},
		{"payload to empty", func(e Envelope) Envelope { e.Message.Payload = ""; return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q, _ := openTempQueue(t)
			defer q.Close()

			first, err := q.Submit(base)
			if err != nil {
				t.Fatal(err)
			}
			changed := tc.mutate(base)
			if _, err := q.Submit(changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("want ErrConflict, got %v", err)
			}

			if len(q.records) != 1 || q.order.len() != 1 || q.order.ids()[0] != "m" || q.nextSeq != 1 {
				t.Fatalf("rejected submit must persist nothing: records=%d order=%v nextSeq=%d",
					len(q.records), q.order.ids(), q.nextSeq)
			}
			got := statusOf(t, q, "m")
			if got.Msg != base {
				t.Fatalf("original content overwritten:\nwant %+v\ngot  %+v", base, got.Msg)
			}
			if got.Status != StatusPending || got.Reason != "awaiting first processing" ||
				got.Attempts != 0 || got.NextRetry != 0 {
				t.Fatalf("pending state changed on conflict: %+v", got)
			}

			// The rejected submit must not have consumed a seq: a later new
			// message still takes seq 1, and an identical resubmit still works.
			if again, err := q.Submit(base); err != nil || again.Seq != first.Seq {
				t.Fatalf("identical resubmit after rejected submit must return original (seq %d): rec=%+v err=%v",
					first.Seq, again, err)
			}
			later := fullEnvelope("n")
			rec, err := q.Submit(later)
			if err != nil {
				t.Fatal(err)
			}
			if rec.Seq != 1 {
				t.Fatalf("rejected submit must not consume a seq number: got %d", rec.Seq)
			}
		})
	}
}

// Content identity must not collapse to the replay triple: same id and same
// (from, to, nonce) but different payload, proof height or expiry is still a
// conflict, in both comparison directions.
func TestSubmitConflictNotJudgedByIdOrNonceOnly(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	first := fullEnvelope("m")
	if _, err := q.Submit(first); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Message.Payload = "different"
	second.Message.ProofAt = 91
	second.ExpiresAt = 1
	if _, err := q.Submit(second); !errors.Is(err, ErrConflict) {
		t.Fatalf("same id/nonce triple but different content must conflict: %v", err)
	}
	// And the reverse ordering of the two contents must give the same verdict.
	if _, err := q.Submit(first); err != nil {
		t.Fatalf("original content must still resubmit idempotently after rejection: %v", err)
	}
}

// A successful idempotent resubmit on a pending record returns a value equal to
// the first submit echo and to what Query reports; Queries still lists the id
// exactly once with its original seq, including across a reopen.
func TestSubmitIdenticalPendingEchoMatchesQueryAndSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := fullEnvelope("m")
	first, err := q.Submit(want)
	if err != nil {
		t.Fatal(err)
	}
	again, err := q.Submit(want)
	if err != nil {
		t.Fatalf("identical pending resubmit: %v", err)
	}
	if *again != *first {
		t.Fatalf("resubmit echo differs from first submit:\nfirst=%+v\nagain=%+v", first, again)
	}
	qy, ok := q.Query("m")
	if !ok {
		t.Fatal("missing m")
	}
	if qy.ID != want.Message.ID || qy.From != want.Message.From || qy.To != want.Message.To ||
		qy.Nonce != want.Message.Nonce || qy.Payload != want.Message.Payload ||
		qy.ProofAt != want.Message.ProofAt || qy.ExpiresAt != want.ExpiresAt ||
		qy.Status != StatusPending || qy.Attempts != 0 || qy.NextRetry != 0 {
		t.Fatalf("query disagrees with resubmit echo: %+v echo=%+v", qy, again)
	}
	if all := q.Queries(); len(all) != 1 || all[0].ID != "m" {
		t.Fatalf("listing must contain the id exactly once: %+v", all)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	if _, err := q2.Submit(want); err != nil {
		t.Fatalf("identical resubmit after reopen must still be idempotent: %v", err)
	}
	if all := q2.Queries(); len(all) != 1 || all[0].ID != "m" || all[0].Payload != want.Message.Payload {
		t.Fatalf("duplicate persisted across reopen: %+v", all)
	}
}

// While waiting, an identical resubmit returns the CURRENT waiting record —
// status, reason, attempts and next retry time all populated — equal to the
// single Query view; it neither processes early nor reschedules. The message
// later delivers exactly on its original schedule.
func TestSubmitIdenticalWaitingReturnsCurrentRecord(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("chain-a")
	q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true})

	env := Envelope{
		Message:   Message{ID: "w", From: "chain-a", To: "chain-b", Nonce: 8, Payload: "world", ProofAt: 110},
		ExpiresAt: 9_000_000_000_000,
	}
	if _, err := q.Submit(env); err != nil {
		t.Fatal(err)
	}
	rep, err := q.Advance(1_700_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusWaiting {
		t.Fatalf("setup: want one waiting result, got %+v", rep.Results)
	}

	echo, err := q.Submit(env)
	if err != nil {
		t.Fatalf("identical waiting resubmit: %v", err)
	}
	if echo.Status != StatusWaiting || echo.Attempts != 1 || echo.NextRetry != 1_700_000_001_000 ||
		echo.Msg != env {
		t.Fatalf("resubmit must return the current waiting record: %+v", echo)
	}
	qy, ok := q.Query("w")
	if !ok {
		t.Fatal("missing w")
	}
	if qy.Status != echo.Status || qy.Reason != echo.Reason || qy.Attempts != echo.Attempts ||
		qy.NextRetry != echo.NextRetry || qy.ExpiresAt != echo.Msg.ExpiresAt {
		t.Fatalf("query disagrees with waiting echo: query=%+v echo=%+v", qy, echo)
	}
	if wantReason := "waiting for trusted header covering height 110 (current 100)"; qy.Reason != wantReason {
		t.Fatalf("waiting reason wrong: %q", qy.Reason)
	}
	if q.order.len() != 1 || len(q.records) != 1 {
		t.Fatalf("waiting duplicate must not add a queue entry: order=%v records=%d", q.order.ids(), len(q.records))
	}

	// Early advance (before retry) processes nothing and keeps the schedule.
	rep, err = q.Advance(1_700_000_000_500)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 0 {
		t.Fatalf("nothing due mid-backoff, got %+v", rep.Results)
	}
	echo2, err := q.Submit(env)
	if err != nil {
		t.Fatal(err)
	}
	if echo2.Status != StatusWaiting || echo2.Attempts != 1 || echo2.NextRetry != 1_700_000_001_000 {
		t.Fatalf("waiting record must be unchanged after early advance: %+v", echo2)
	}

	// Coverage arrives, delivery happens only at the scheduled retry.
	q.UpsertHeader(Header{Chain: "chain-a", Height: 110, Root: "0x110", Trusted: true})
	rep, err = q.Advance(1_700_000_001_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Status != StatusSuccess {
		t.Fatalf("want delivery at scheduled retry, got %+v", rep.Results)
	}
}

// A conflicting submit against a waiting record leaves its content, status,
// reason, attempt count and retry schedule exactly as they were, including
// when only the proof height or the expiry changes.
func TestSubmitConflictWhileWaitingKeepsRecordAndSchedule(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()
	q.RegisterSource("chain-a")
	q.UpsertHeader(Header{Chain: "chain-a", Height: 100, Root: "0x100", Trusted: true})

	env := Envelope{
		Message:   Message{ID: "w", From: "chain-a", To: "chain-b", Nonce: 8, Payload: "world", ProofAt: 110},
		ExpiresAt: 9_000_000_000_000,
	}
	q.Submit(env)
	q.Advance(1_700_000_000_000)
	before := statusOf(t, q, "w")
	beforeQ, _ := q.Query("w")

	for _, mutate := range []func(Envelope) Envelope{
		func(e Envelope) Envelope { e.Message.ProofAt = 111; return e },
		func(e Envelope) Envelope { e.ExpiresAt = 9_000_000_000_001; return e },
		func(e Envelope) Envelope { e.Message.Payload = "WORLD"; return e },
		func(e Envelope) Envelope { e.Message.Nonce = 9; return e },
		func(e Envelope) Envelope { e.Message.From = "chain-a2"; return e },
		func(e Envelope) Envelope { e.Message.To = "chain-c"; return e },
	} {
		if _, err := q.Submit(mutate(env)); !errors.Is(err, ErrConflict) {
			t.Fatalf("waiting content change must be ErrConflict: %v", err)
		}
		got := statusOf(t, q, "w")
		if got.Status != before.Status || got.Reason != before.Reason ||
			got.Attempts != before.Attempts || got.NextRetry != before.NextRetry ||
			got.Msg != before.Msg {
			t.Fatalf("waiting record changed on rejected submit:\nbefore=%+v\nafter =%+v", before, got)
		}
	}
	if got, _ := q.Query("w"); got != beforeQ {
		t.Fatalf("query view changed: %+v", got)
	}
	if q.order.len() != 1 {
		t.Fatalf("conflict added a queue entry: %v", q.order.ids())
	}
}

// A rejected submit against one message changes neither sibling content nor
// the first-submission order of the live records.
func TestSubmitConflictLeavesSiblingsAndOrderUntouched(t *testing.T) {
	q, _ := openTempQueue(t)
	defer q.Close()

	a := env("a", "a", "b", 1, 10, 0)
	m := Envelope{Message: Message{ID: "m", From: "a", To: "b", Nonce: 5, Payload: "orig", ProofAt: 20}, ExpiresAt: 0}
	b := env("b", "a", "b", 9, 30, 0)
	for _, e := range []Envelope{a, m, b} {
		if _, err := q.Submit(e); err != nil {
			t.Fatal(err)
		}
	}

	bad := m
	bad.Message.ProofAt = 21
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}

	all := q.Queries()
	if len(all) != 3 || all[0].ID != "a" || all[1].ID != "m" || all[2].ID != "b" {
		t.Fatalf("order changed by rejected submit: %+v", all)
	}
	if all[1].Payload != "orig" || all[1].ProofAt != 20 {
		t.Fatalf("target content overwritten: %+v", all[1])
	}
	if all[0].ProofAt != 10 || all[2].ProofAt != 30 {
		t.Fatalf("sibling content changed: %+v %+v", all[0], all[2])
	}
}

// A rejected conflict must survive a process restart with nothing added: only
// the original record exists, with the original content, pending state and
// seq.
func TestSubmitConflictPersistsNothingAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	base := fullEnvelope("m")
	if _, err := q.Submit(base); err != nil {
		t.Fatal(err)
	}
	bad := base
	bad.Message.ProofAt = 1000
	if _, err := q.Submit(bad); !errors.Is(err, ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer q2.Close()
	if len(q2.records) != 1 || q2.nextSeq != 1 {
		t.Fatalf("rejected submit leaked into the log: records=%d nextSeq=%d", len(q2.records), q2.nextSeq)
	}
	got := statusOf(t, q2, "m")
	if got.Msg != base || got.Status != StatusPending {
		t.Fatalf("record after reopen wrong: %+v", got)
	}
	// Original content still resubmits idempotently after reopen.
	if _, err := q2.Submit(base); err != nil {
		t.Fatalf("identical resubmit after reopen: %v", err)
	}
	if len(q2.records) != 1 {
		t.Fatal("identical resubmit after reopen added a record")
	}
}

// Once a message is terminal, identical and differing content alike return
// ErrTerminal (never ErrConflict), for success as well as the other terminal
// statuses; the stored record stays queryable with its status and reason.
func TestSubmitTerminalIDAlwaysErrTerminal(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		q.RegisterSource("a")
		q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
		e := env("m", "a", "b", 1, 10, 0)
		q.Submit(e)
		q.Advance(1000)

		if _, err := q.Submit(e); !errors.Is(err, ErrTerminal) {
			t.Fatalf("identical resubmit of a success: want ErrTerminal, got %v", err)
		}
		bad := e
		bad.Message.ProofAt = 11
		if _, err := q.Submit(bad); !errors.Is(err, ErrTerminal) {
			t.Fatalf("different content on a success: want ErrTerminal, got %v", err)
		}
		got := statusOf(t, q, "m")
		if got.Status != StatusSuccess || got.NextRetry != 0 {
			t.Fatalf("success record changed: %+v", got)
		}
		// Advancing time again must not redeliver.
		rep, err := q.Advance(2000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rep.Results) != 0 {
			t.Fatalf("terminal message reappeared on advance: %+v", rep.Results)
		}
	})

	t.Run("expired", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		q.RegisterSource("a")
		e := env("m", "a", "b", 1, 1000, 2000)
		q.Submit(e)
		q.Advance(1000) // waiting
		q.Advance(2000) // expired
		if _, err := q.Submit(e); !errors.Is(err, ErrTerminal) {
			t.Fatalf("identical resubmit of expired: %v", err)
		}
		bad := e
		bad.Message.Payload = "x"
		if _, err := q.Submit(bad); !errors.Is(err, ErrTerminal) {
			t.Fatalf("different content on expired: want ErrTerminal, got %v", err)
		}
		if got := statusOf(t, q, "m"); got.Status != StatusExpired {
			t.Fatalf("expired record changed: %+v", got)
		}
	})

	t.Run("unknown-source", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		e := env("m", "ghost", "b", 1, 10, 0)
		q.Submit(e)
		q.Advance(1000)
		if _, err := q.Submit(e); !errors.Is(err, ErrTerminal) {
			t.Fatalf("identical resubmit of unknown-source: %v", err)
		}
		bad := e
		bad.Message.ProofAt = 11
		if _, err := q.Submit(bad); !errors.Is(err, ErrTerminal) {
			t.Fatalf("different content on unknown-source: want ErrTerminal, got %v", err)
		}
		if got := statusOf(t, q, "m"); got.Status != StatusUnknownSrc {
			t.Fatalf("unknown-source record changed: %+v", got)
		}
	})

	t.Run("replay", func(t *testing.T) {
		q, _ := openTempQueue(t)
		defer q.Close()
		q.RegisterSource("a")
		q.UpsertHeader(Header{Chain: "a", Height: 100, Trusted: true})
		winner := env("win", "a", "b", 3, 10, 0)
		loser := env("lose", "a", "b", 3, 10, 0)
		q.Submit(winner)
		q.Submit(loser)
		q.Advance(1000)
		if _, err := q.Submit(loser); !errors.Is(err, ErrTerminal) {
			t.Fatalf("identical resubmit of replay record: %v", err)
		}
		bad := loser
		bad.Message.Payload = "p-changed"
		if _, err := q.Submit(bad); !errors.Is(err, ErrTerminal) {
			t.Fatalf("different content on replay record: want ErrTerminal, got %v", err)
		}
		if got := statusOf(t, q, "lose"); got.Status != StatusReplay {
			t.Fatalf("replay record changed: %+v", got)
		}
	})
}
