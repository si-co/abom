package scheme

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/stretchr/testify/require"
)

var ps0 = []byte{1, 2, 3, 4}

func initStates() ([]byte, *DeviceState, *ServerState) {
	kappa := RandomKey256()
	k := RandomKey128()

	// 1. Client sets up
	ds, cm := ClientSetup(kappa, k, ps0)

	// 2. Server processes client message and responds
	_, ss, sm := ServerSetup(kappa, cm)

	// 3. Client processes server response
	_, ds = ClientDone(ds, sm)

	return k, ds, ss
}

func TestSetup(t *testing.T) {
	kappa := RandomKey256()
	k := RandomKey128()

	// 1. Client sets up
	ds, cm := ClientSetup(kappa, k, ps0)

	// 2. Server processes client message and responds
	acc, ss, sm := ServerSetup(kappa, cm)
	require.True(t, acc, "Server should accept initial message")

	// 3. Client processes server response
	acc2, ds2 := ClientDone(ds, sm)
	require.True(t, acc2, "Client should accept server response")

	// Optional: Additional state checks
	require.NotNil(t, ss)
	require.NotNil(t, ds2)
	require.Equal(t, ds2.cnt_cm, ss.cnt_cm, "cnt_cm should be in sync")
	require.Equal(t, ds2.cnt_sm, ss.cnt_sm, "cnt_sm should be in sync")
}

func TestProtocolFlow(t *testing.T) {
	kappa := RandomKey256()
	k := RandomKey128()

	shouldDetect := false

	ds, cm := ClientSetup(kappa, k, ps0)

	acc, ss, sm := ServerSetup(kappa, cm)
	require.True(t, acc, "Server should accept initial setup message")

	acc, ds = ClientDone(ds, sm)
	require.True(t, acc, "Client should accept server response")

	ds, cm = Request(ds, ps0)

	var detect bool
	acc, _, detect, sm = Response(ss, cm)
	require.True(t, acc, "Server should accept client request")
	require.Equal(t, shouldDetect, detect)

	var derivedKey []byte
	acc, _, derivedKey = GetKey(ds, sm)
	require.True(t, acc, "Client should derive key")
	require.NotNil(t, derivedKey)

	require.True(t, bytes.Equal(derivedKey, k), "Derived key does not match initial key")
}

func basicTest(t *testing.T, key []byte, ds *DeviceState, ss *ServerState, ps []byte, shouldDetect bool) {
	// client sends request
	ds, cm := Request(ds, ps)

	// server replies
	acc, _, detect, sm := Response(ss, cm)
	require.True(t, acc)
	require.Equal(t, shouldDetect, detect)

	// final get key
	ok, _, derivedKey := GetKey(ds, sm)
	require.True(t, ok)
	require.NotNil(t, derivedKey)

	// --- Check if derived key equals initial key ---
	require.True(t, bytes.Equal(derivedKey, key))
}

func TestSchemeGood(t *testing.T) {
	key, ds, ss := initStates()

	basicTest(t, key, ds, ss, ps0, false)
}

func TestSchemeWrongPS(t *testing.T) {
	ps := []byte("4567")
	key, ds, ss := initStates()

	basicTest(t, key, ds, ss, ps, !bytes.Equal(ps0, ps))
}

func TestMultipleMessages(t *testing.T) {
	ps := []byte("4567")
	key, ds, ss := initStates()

	for range rand.IntN(48) {
		basicTest(t, key, ds, ss, ps, !bytes.Equal(ps0, ps))
	}
}

func TestTamperCmCounter(t *testing.T) {
	ps := []byte("4567")
	_, ds, ss := initStates()

	// client request
	_, cm := Request(ds, ps)

	// attack
	tampered := cm
	tampered.AD[0] = 10 // <-- attacker injects wrong counter
	tampered.AD[1] = 10 // <-- attacker injects wrong counter

	// server gets tampered cm
	acc, _, _, _ := Response(ss, tampered)

	// --- Expect failure (MAC mismatch due to wrong key) ---
	require.False(t, acc, "MAC verification should fail when cnt_cm is tampered")
}

func TestTamperSmCounter(t *testing.T) {
	ps := []byte("4567")
	_, ds, ss := initStates()

	// client request
	ds, cm := Request(ds, ps)

	// server replies
	acc, _, detect, sm := Response(ss, cm)
	require.True(t, acc)
	require.True(t, detect)

	// attack
	tampered := sm
	tampered.AD[0] = 10 // <-- attacker injects wrong counter
	tampered.AD[1] = 10 // <-- attacker injects wrong counter

	// final get key
	acc, _, derivedKey := GetKey(ds, tampered)
	require.False(t, acc, "MAC verification should fail when cnt_cm is tampered")
	require.Nil(t, derivedKey)

	// --- Expect failure (MAC mismatch due to wrong key) ---
}

func TestDelayedDeliveryOfTenthMessage(t *testing.T) {
	ps := []byte("4567")
	key, ds, ss := initStates()

	var finalCM Message

	// sender generates 10 messages, but only the 10th is delivered
	for range 10 {
		ds, finalCM = Request(ds, ps)
	}

	// receiver only sees the 10th message
	acc, _, detect, sm := Response(ss, finalCM)

	// --- This should succeed: fastForward covers skipped messages ---
	require.True(t, acc, "receiver should accept the 10th message despite delay")
	require.True(t, detect)

	// --- Sender gets response and recovers key ---
	ok, _, derivedKey := GetKey(ds, sm)
	require.True(t, ok)
	require.True(t, bytes.Equal(derivedKey, key), "Derived key should match original")
}

func TestReplayRejected(t *testing.T) {
	ps := []byte("4567")
	_, ds, ss := initStates()

	// Generate and deliver one message
	var cm Message
	ds, cm = Request(ds, ps)

	// Deliver message once (normal path)
	acc1, ss1, detect1, sm1 := Response(ss, cm)
	require.True(t, acc1)
	require.True(t, detect1)
	ok, _, _ := GetKey(ds, sm1)
	require.True(t, ok)

	// Save state snapshot
	ssBefore := *ss1

	// Replay the same message
	acc2, ss2, detect2, _ := Response(ss1, cm)
	require.False(t, acc2, "replay should be rejected")
	require.False(t, detect2)

	// State must not have changed
	require.Equal(t, ssBefore, *ss2, "state must remain unchanged on replay")
}

func TestClear(t *testing.T) {
	ps := []byte("4567")
	key, ds, ss := initStates()

	// complete execution
	basicTest(t, key, ds, ss, ps, true)

	// useless clear
	ds = Clear(ds)

	// partial execution

	// client sends request
	ds, cm := Request(ds, ps)

	// server replies
	acc, _, detect, _ := Response(ss, cm)
	require.True(t, acc)
	require.True(t, detect)

	// useful clear
	ds = Clear(ds)

	// new execution
	basicTest(t, key, ds, ss, ps, true)
}

func TestClearTwoMessages(t *testing.T) {
	ps := []byte("4567")
	_, ds, ss := initStates()

	// generate first message
	var cm1 Message
	ds, cm1 = Request(ds, ps)

	// generate second message
	var cm2 Message
	ds, cm2 = Request(ds, ps)

	// get first sm
	var acc1 bool
	var detect1 bool
	var sm1 Message
	acc1, ss, detect1, sm1 = Response(ss, cm1)
	require.True(t, acc1)
	require.True(t, detect1)

	var acc2 bool
	var detect2 bool
	var sm2 Message
	// get second sm
	acc2, ss, detect2, sm2 = Response(ss, cm2)
	require.True(t, acc2)
	require.True(t, detect2)

	// process first sm1, should be ok
	var ok1 bool
	ok1, ds, _ = GetKey(ds, sm1)
	require.True(t, ok1)

	// call to clar
	ds = Clear(ds)

	// process second sm, should be rejected
	var ok2 bool
	ok2, ds, _ = GetKey(ds, sm2)
	require.False(t, ok2)
}

func TestClearThreeMessages(t *testing.T) {
	ps := []byte("4567")
	_, ds, ss := initStates()

	// generate first message
	var cm1 Message
	ds, cm1 = Request(ds, ps)

	// generate second message
	var cm2 Message
	ds, cm2 = Request(ds, ps)

	// generate third message
	var cm3 Message
	ds, cm3 = Request(ds, ps)

	// get first sm
	var acc1 bool
	var detect1 bool
	var sm1 Message
	acc1, ss, detect1, sm1 = Response(ss, cm1)
	require.True(t, acc1)
	require.True(t, detect1)

	var acc2 bool
	var detect2 bool
	var sm2 Message
	// get second sm
	acc2, ss, detect2, sm2 = Response(ss, cm2)
	require.True(t, acc2)
	require.True(t, detect2)

	var acc3 bool
	var detect3 bool
	var sm3 Message
	// get second sm
	acc3, ss, detect3, sm3 = Response(ss, cm3)
	require.True(t, acc3)
	require.True(t, detect3)

	// process first sm1, should be ok
	var ok1 bool
	ok1, ds, _ = GetKey(ds, sm1)
	require.True(t, ok1)

	// call to clar
	ds = Clear(ds)

	// process second sm, should be rejected
	var ok2 bool
	ok2, ds, _ = GetKey(ds, sm2)
	require.False(t, ok2, "second message should be impossible to receive")

	// process second sm, should be rejected
	var ok3 bool
	ok3, ds, _ = GetKey(ds, sm3)
	require.False(t, ok3, "third message should be impossible to receive")
}

func TestClearMultipleMessages(t *testing.T) {
	ps := []byte("4567")

	for n := 2; n <= 10; n++ { // test with 2…10 messages; adjust as needed
		t.Run(fmt.Sprintf("%d_messages", n), func(t *testing.T) {
			_, ds, ss := initStates()

			// --- generate n client messages ------------------------------
			cms := make([]Message, n)
			for i := range n {
				var cm Message
				ds, cm = Request(ds, ps)
				cms[i] = cm
			}

			// --- obtain n server messages --------------------------------
			sms := make([]Message, n)
			for i := range n {
				var acc, detect bool
				var sm Message
				acc, ss, detect, sm = Response(ss, cms[i])
				require.True(t, acc, "cm%d not accepted", i+1)
				require.True(t, detect, "cm%d not detected as valid", i+1)
				sms[i] = sm
			}

			// --- process the first server message (should succeed) -------
			ok, ds, _ := GetKey(ds, sms[0])
			require.True(t, ok, "first message should be accepted")

			// --- clear state ---------------------------------------------
			ds = Clear(ds)

			// --- remaining messages must now be rejected -----------------
			for i := 1; i < n; i++ {
				ok, ds, _ = GetKey(ds, sms[i])
				require.False(t, ok, "message %d should be rejected", i+1)
			}
		})
	}
}

func TestClearRandomPoint(t *testing.T) {
	numMsgs := 100

	ps := []byte("4567")

	// where to clear
	clearAt := rand.IntN(numMsgs)

	_, ds, ss := initStates()

	cms := make([]Message, numMsgs)
	for i := range cms {
		ds, cms[i] = Request(ds, ps)
	}

	sms := make([]Message, numMsgs)
	for i := range cms {
		var acc, detect bool
		acc, ss, detect, sms[i] = Response(ss, cms[i])
		require.True(t, acc, "cm%d not accepted", i+1)
		require.True(t, detect, "cm%d not detected", i+1)
	}

	for i := 0; i <= clearAt; i++ {
		ok, nds, _ := GetKey(ds, sms[i])
		require.True(t, ok, "msg %d should be accepted before Clear", i+1)
		ds = nds
	}

	ds = Clear(ds)

	for i := clearAt + 1; i < numMsgs; i++ {
		ok, nds, _ := GetKey(ds, sms[i])
		require.False(t, ok, "msg %d should be rejected after Clear", i+1)
		ds = nds
	}
}

/*
Proposed attack, this test shows that it *doesn't* work:

1. The client sends a genuine request Request. I write c for \mathsf{cnt}_{\mathsf{cm}} and s for \mathsf{cnt}_{\mathsf{sm}}. We have c=1, s=0
2. The adversary sends that same request to the server, say, 10 times. We have c=1 and s=10. It blocks the responses going through except for the last one. This syncronises the s=10 to the client.
3. The client sends another request and we have c=2. The adversary holds on to it.
4. The client calls Clear which doesn't ratchet forward at all because s > c
5. The adversary allows the suppressed client request and the server response go through.
6. The client recovers the key for a request it sent before calling Clear: it hasn't ratcheted forward past the point where it can decrypt the server's response
*/
func TestAttackResponse(t *testing.T) {
	ps := []byte("4567")
	_, ds, ss := initStates()

	// 1. The client sends a genuine request Request.
	var cm1 Message
	ds, cm1 = Request(ds, ps)

	// at this point on the client we should have cnt_cm = 2 (one
	// ClientSetup message, one Request message) and cnt_sm = 1 (one
	// ServerSetup message)
	cnt_cmClient, cnt_smClient := GetCountersClient(ds)
	require.EqualValues(t, 2, cnt_cmClient)
	require.EqualValues(t, 1, cnt_smClient)

	// The server receives the genuine request
	var acc1 bool
	var detect1 bool
	acc1, ss, detect1, _ = Response(ss, cm1)
	require.True(t, acc1)
	require.True(t, detect1)

	// at this point on the server we should have cnt_cm = 2 (one
	// ClientSetup message, one Request message) and cnt_sm = 2 (one
	// ServerSetup message and one response)
	cnt_cmServer, cnt_smServer := GetCountersServer(ss)
	require.EqualValues(t, 2, cnt_cmServer)
	require.EqualValues(t, 2, cnt_smServer)

	// 2. The adversary sends that same request to the server, say, 10 times.
	// These should be rejected because they're replies
	sms := make([]Message, 10)
	for i := range 10 {
		var acc bool
		_, ss, _, sms[i] = Response(ss, cm1)
		require.False(t, acc, "cm%d accepted while it shouldn't", i+1)
	}

	// get and verify counters on the server. We have cnt_smServer since
	// one setup message and one valid response
	cnt_cmServer, cnt_smServer = GetCountersServer(ss)
	require.EqualValues(t, 2, cnt_cmServer, "cnt_cm on the server wrong")
	require.EqualValues(t, 2, cnt_smServer, "cnt_sm on the server wrong")

	// this should be rejected because sms[9] was rejected and
	// it therefore an invalid message
	var ok10 bool
	ok10, ds, _ = GetKey(ds, sms[9])
	require.False(t, ok10)

	// get and verify counters
	cnt_cmClient, cnt_smClient = GetCountersClient(ds)
	require.EqualValues(t, 2, cnt_cmClient)
	require.EqualValues(t, 1, cnt_smClient)

	// the client at this point sends another legitimate cm, which should go through
	var cm2 Message
	ds, cm2 = Request(ds, ps)

	// at this point on the client we should have cnt_cm = 2 (one
	// ClientSetup message, two Request messages) and cnt_sm = 1 (one
	// ServerSetup message and one response that never arrived to the client, so only
	// the setup message)
	cnt_cmClient, cnt_smClient = GetCountersClient(ds)
	require.EqualValues(t, 3, cnt_cmClient)
	require.EqualValues(t, 1, cnt_smClient)

	// this call should set cnt_smClient to the value of cnt_cmClient, i.e., to 3
	ds = Clear(ds)

	// verify that Clear actually moved the counters
	cnt_cmClient, cnt_smClient = GetCountersClient(ds)
	require.EqualValues(t, 3, cnt_cmClient)
	require.EqualValues(t, 3, cnt_smClient)

	var acc2 bool
	var detect2 bool
	var sm2 Message
	acc2, ss, detect2, sm2 = Response(ss, cm2)
	require.True(t, acc2)
	require.True(t, detect2)

	// at this point on the server we should have cnt_cm = 3 and cnt_sm = 3
	// because one setup message and two valid responses)
	cnt_cmServer, cnt_smServer = GetCountersServer(ss)
	require.EqualValues(t, 3, cnt_cmServer, "cnt_cm on the server wrong")
	require.EqualValues(t, 3, cnt_smServer, "cnt_sm on the server wrong")

	// process second sm, should be rejected. This is correctly
	// rejected because we on the client we have cnt_smServer = 3 and
	// and the message that comes from the server has cnt_sm' = 3,
	// so FtK returns \bot as key and rejected
	_, cnt_smClient = GetCountersClient(ds)
	require.EqualValues(t, 3, cnt_smClient)
	require.EqualValues(t, 3, sm2.AD[1])
	var ok2 bool
	ok2, ds, _ = GetKey(ds, sm2)
	require.False(t, ok2, "second message should be impossible to receive")
}
