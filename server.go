package scheme

import (
	"crypto/hmac"
)

// ServerState holds the server's local state:
//
//   - k1: server share used to reconstruct k (k = k0 xor k1)
//   - com: commitment to the real ps
//   - rs_cm, rs_sm: ratchet states for client messages (rs_cm) and server
//     messages (rs_sm)
//   - cnt_cm, cnt_sm: counters for client messages and server messages
//
// Field names use underscores for parity with the spec.
type ServerState struct {
	k1  []byte
	com []byte

	rs_cm, rs_sm   []byte
	cnt_cm, cnt_sm uint64
}

// ServerSetup verifies the client's initial message cm, binds the commitment
// and k_1 into server state, and returns an authenticated ack.  On failure it
// returns acc=false, no server state, and a zero message.
func ServerSetup(kappa []byte, cm Message) (bool, *ServerState, Message) {
	// ratchet states (line 1)
	rs_cm, rs_sm := KDF(kappa)

	// init counters (line 2)
	cnt_cm, cnt_sm := uint64(0), uint64(0)

	// parse cm (line 3)
	ct := cm.Ciphertext
	at := cm.AuthTag
	cnt_cm_prime := cm.AD[0]
	cnt_sm_prime := cm.AD[1]

	// FtK on rs_cm (line 4)
	k_cm, rs_cm, cnt_cm := FtK(rs_cm, cnt_cm, cnt_cm_prime)

	// VtD on pt = (com, k1) (line 5)
	acc, pt := VtD(k_cm, ct, at, [2]uint64{cnt_cm_prime, cnt_sm_prime})

	// if fail return (line 6)
	if !acc {
		return false, nil, Message{}
	}

	// parse pt (line 7)
	com := pt[:32]
	k1 := pt[32:]

	// increase sm counter (line 8)
	cnt_sm++

	// KDF on rs_sm (line 9)
	k_sm, rs_sm := KDF(rs_sm)

	// encrypt ok (need 16 bytes message for AES-CBC) (line 10)
	ct, at = EtM(k_sm, []byte("server says: OK."), [2]uint64{cnt_cm, cnt_sm})

	// store server state (line 11)
	ss := &ServerState{
		rs_cm:  rs_cm,
		rs_sm:  rs_sm,
		cnt_cm: cnt_cm,
		cnt_sm: cnt_sm,
		com:    com,
		k1:     k1,
	}

	// return (line 12)
	sm := Message{
		Ciphertext: ct,
		AuthTag:    at,
		AD:         [2]uint64{cnt_cm, cnt_sm},
	}

	return true, ss, sm
}

// Response verifies a client request cm, checks the commitment against the one
// established at setup, and returns k_1 if valid. The detect flag is true when
// the request's commitment differs from the commitment to the real personal
// secret com, which the server stores in its the local state.
//
// On authentication failure it returns acc=false and a zero message.
func Response(ss *ServerState, cm Message) (bool, *ServerState, bool, Message) {
	// extract fields from ss (line 1)
	rs_cm := ss.rs_cm
	rs_sm := ss.rs_sm
	cnt_cm := ss.cnt_cm
	cnt_sm := ss.cnt_sm
	com := ss.com
	k1 := ss.k1

	// extract fields from sm (line 2)
	ct := cm.Ciphertext
	at := cm.AuthTag
	cnt_cm_prime := cm.AD[0]
	cnt_sm_prime := cm.AD[1]

	// FtK on rs_cm (line 3)
	k_cm, rs_cm, cnt_cm := FtK(rs_cm, cnt_cm, cnt_cm_prime)

	// VtD (line 4)
	acc, com_prime := VtD(k_cm, ct, at, [2]uint64{cnt_cm_prime, cnt_sm_prime})

	// if failure, return (line 5)
	if !acc {
		return false, ss, false, Message{}
	}

	// check commitment (line 6)
	detect := !hmac.Equal(com, com_prime)

	// FtK on rs_sm (line 7)
	_, rs_sm, cnt_sm = FtK(rs_sm, cnt_sm, cnt_sm_prime)

	// increment counter (line 8)
	cnt_sm++

	// apply KDF on rs_sm (line 9)
	k_sm, rs_sm := KDF(rs_sm)

	// EtM with k_1 as plaintext (line 10)
	ct, at = EtM(k_sm, k1, [2]uint64{cnt_cm, cnt_sm})

	// Update server state (lines 11 and 12)
	ss.rs_cm = rs_cm
	ss.rs_sm = rs_sm
	ss.cnt_cm = cnt_cm
	ss.cnt_sm = cnt_sm

	// Return (line 13)
	return acc, ss, detect, Message{
		Ciphertext: ct,
		AuthTag:    at,
		AD:         [2]uint64{cnt_cm, cnt_sm},
	}
}

// GetCountersServer retruns the counters from the server state.
func GetCountersServer(ss *ServerState) (uint64, uint64) {
	return ss.cnt_cm, ss.cnt_sm
}
