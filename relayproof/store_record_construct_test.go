package relayproof

// These tests pin the refactor that makes the plain append path and the log
// compaction path construct message records through the same rules: a submit
// record comes from newSubmitEntry in both paths, and a processed record
// (kindResult vs kindState) carries byte-identical fields regardless of which
// path built it. The end-to-end reopen/compaction behavior is covered by the
// per-field byte tests; this guards the two construction paths against
// drifting apart again.

import (
	"encoding/json"
	"testing"
)

// marshalEntry renders an entry the way the log frame stores it.
func marshalEntry(t *testing.T, e *logEntry) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSubmitEntrySharedByBothPaths checks that a submission keeps its id,
// destination and payload bytes through the single submit constructor the
// append and compaction paths share. Both paths must emit exactly one record
// shape, including invalid UTF-8 in every split field and an empty payload.
func TestSubmitEntrySharedByBothPaths(t *testing.T) {
	env := Envelope{
		Message: Message{
			ID:    "id-" + string([]byte{0xFF, 0xFE}),
			From:  "src",
			To:    "dst:" + string([]byte{0xFF, 0x00}),
			Nonce: 42,
			// Raw invalid bytes mixed with text, then an empty-payload case.
			Payload: "p:" + string([]byte{0xFF}),
			ProofAt: 7,
		},
		ExpiresAt: 9000,
	}
	e := newSubmitEntry(3, env)
	if e.T != kindSubmit {
		t.Fatalf("kind = %q, want %q", e.T, kindSubmit)
	}
	round := func(payload string) {
		env.Message.Payload = payload
		got := marshalEntry(t, newSubmitEntry(3, env))
		// Re-decode through the replay normalizer: the saved bytes must come
		// back exactly, never as replacement characters.
		var decoded logEntry
		if err := json.Unmarshal(got, &decoded); err != nil {
			t.Fatal(err)
		}
		if err := normalizeEntryRaw(&decoded); err != nil {
			t.Fatal(err)
		}
		p, err := decoded.entryPayload()
		if err != nil {
			t.Fatal(err)
		}
		if p != payload {
			t.Fatalf("payload round trip = %q, want %q", p, payload)
		}
		if decoded.ID != env.Message.ID || decoded.To != env.Message.To {
			t.Fatalf("id/to round trip = %q/%q, want %q/%q",
				decoded.ID, decoded.To, env.Message.ID, env.Message.To)
		}
	}
	round(env.Message.Payload)
	round("") // the legal empty payload stays legal on both paths
}

// TestProcessedEntrySameFieldsOnBothPaths builds the processed entry for each
// status exactly the way the two callers do — appendOutcome straight from the
// outcome, compaction from the persisted Record — and asserts the two entries
// serialize identically apart from the on-disk kind. Raw bytes appear in the
// id and in every reason (replay and unknown-source reasons embed an id or
// chain name), and success carries its own consumption triple attributed to
// the message.
func TestProcessedEntrySameFieldsOnBothPaths(t *testing.T) {
	const now = 5000
	id := "msg-" + string([]byte{0xFF})
	to := "dst-" + string([]byte{0xFE})

	type shape struct {
		name    string
		status  string
		reason  string
		consume bool
	}
	shapes := []shape{
		{"waiting", StatusWaiting, "waiting for header " + string([]byte{0xFF}), false},
		{"success", StatusSuccess, "delivered at 9", true},
		{"replay", StatusReplay, "consumed by " + id, false},
		{"expired", StatusExpired, "expired at 4000", false},
		{"unknown-source", StatusUnknownSrc, "unknown source chain " + string([]byte{0xFF}), false},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			attempts := 3
			nextRetry := int64(0)
			var token *consumeToken
			if sh.status == StatusWaiting {
				nextRetry = nextRetryAt(now, attempts)
			}
			if sh.consume {
				tk := newConsumeToken("src", to, 42)
				token = &tk
			}

			// Plain append path: fields taken straight from the outcome, like
			// appendOutcome does.
			plain, err := newProcessedEntry(id, processedFields{
				kind: kindResult, now: now, attempts: attempts,
				status: sh.status, reason: sh.reason,
				nextRetry: nextRetry, consume: token,
			})
			if err != nil {
				t.Fatal(err)
			}

			// Snapshot path: fields reconstructed from the persisted record the
			// way compact() does — waiting keeps its retry instant, success
			// rebuilds the message's own triple, other statuses carry neither.
			f := processedFields{
				kind: kindState, now: now, attempts: attempts,
				status: sh.status, reason: sh.reason,
			}
			if sh.status == StatusWaiting {
				f.nextRetry = nextRetry
			}
			if sh.status == StatusSuccess {
				tk := newConsumeToken("src", to, 42)
				f.consume = &tk
			}
			snap, err := newProcessedEntry(id, f)
			if err != nil {
				t.Fatal(err)
			}

			pb := marshalEntry(t, plain)
			sb := marshalEntry(t, snap)
			var pm, sm map[string]json.RawMessage
			if err := json.Unmarshal(pb, &pm); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(sb, &sm); err != nil {
				t.Fatal(err)
			}
			if string(pm["t"]) != `"result"` || string(sm["t"]) != `"state"` {
				t.Fatalf("kind markers = %s / %s", pm["t"], sm["t"])
			}
			delete(pm, "t")
			delete(sm, "t")
			if len(pm) != len(sm) {
				t.Fatalf("field set differs:\nplain: %s\nsnap:  %s", pb, sb)
			}
			for k, pv := range pm {
				if sv, ok := sm[k]; !ok || string(pv) != string(sv) {
					t.Fatalf("field %q differs between paths:\nplain: %s\nsnap:  %s", k, pb, sb)
				}
			}

			// The replay normalizer must recover the exact raw id and reason.
			var decoded logEntry
			if err := json.Unmarshal(sb, &decoded); err != nil {
				t.Fatal(err)
			}
			if err := normalizeEntryRaw(&decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.ID != id {
				t.Fatalf("id round trip = %q, want %q", decoded.ID, id)
			}
			if decoded.Reason != sh.reason {
				t.Fatalf("reason round trip = %q, want %q", decoded.Reason, sh.reason)
			}
			if sh.status == StatusSuccess {
				if decoded.ConsumeTo != to || decoded.ConsumeNonce != 42 ||
					decoded.ConsumeFrom != "src" || decoded.ConsumeBy != id {
					t.Fatalf("success consumption not attributed to the message: %+v", decoded)
				}
			} else if entryCarriesConsumption(&decoded) {
				t.Fatalf("non-success entry carries consumption fields: %+v", decoded)
			}
		})
	}
}

// TestProcessedEntrySuccessWithoutConsumeIsInternalError keeps the historical
// guard: a success state must always name the triple it consumed, on both
// save paths.
func TestProcessedEntrySuccessWithoutConsumeIsInternalError(t *testing.T) {
	if _, err := newProcessedEntry("m", processedFields{
		kind: kindResult, now: 1, attempts: 1, status: StatusSuccess, reason: "ok",
	}); err == nil {
		t.Fatal("success without a consumed triple must fail")
	}
}
