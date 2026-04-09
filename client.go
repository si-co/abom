package scheme

// DeviceState holds the client's local state. All fields are unexported;
// callers interact via the exported functions in this package.
//
//   - k0: client share used to reconstruct k (k = k0 xor k1)
//   - k_com: PRF key for commitments com = PRF(k_com, ps)
//   - rs_cm, rs_sm: ratchet states for client messages (rs_cm) and server
//     messages (rs_sm)
//   - cnt_cm, cnt_sm: counters for client messages and server messages
//
// Field names use underscores for parity with the spec.
type DeviceState struct {
	k0    []byte
	k_com []byte

	rs_cm, rs_sm   []byte
	cnt_cm, cnt_sm uint32
}

// ClientSetup (Figure 5 in the proceedings version, Figure 10 in the full
// version: https://ia.cr/2026/252) initializes a fresh DeviceState, which it
// returns with the initial client message.
//
// Arguments:
//   - kappa: initialization secret shared with the server of 32 bytes.
//   - k: the 16-byte session key.
//   - ps: the client's real personal secret.
//
// The returned client message encrypts (com || k1), where com=PRF(k_com, ps) and
// k1 = k xor k0.
func ClientSetup(kappa, k, ps []byte) (*DeviceState, Message) {
	// ratchet states (line 1)
	rs_cm, rs_sm := KDF(kappa)

	// init counters (line 2)
	cnt_cm, cnt_sm := uint32(0), uint32(0)

	// commitment (line 3)
	k_com := RandomKey256()
	com := PRF(k_com, ps)

	// key and secret sharing (line 4)
	k0 := RandomKey128()
	k1 := xor(k, k0)

	// update counter (line 5)
	cnt_cm = cnt_cm + 1

	// kdf on rs_cm (line 6)
	k_cm, rs_cm := KDF(rs_cm)

	// EtM for (com, k1) (line 7)
	ct, at := EtM(k_cm, append(com, k1...), [2]uint32{cnt_cm, cnt_sm})

	// set device state (line 9)
	ds := &DeviceState{
		k_com:  k_com,
		rs_cm:  rs_cm,
		rs_sm:  rs_sm,
		cnt_cm: cnt_cm,
		cnt_sm: cnt_sm,
		k0:     k0,
	}

	// return (line 10)
	return ds, Message{
		Ciphertext: ct,
		AuthTag:    at,
		AD:         [2]uint32{cnt_cm, cnt_sm},
	}
}

// ClientDone (Figure 5 in the proceedings version, Figure 10 in the full
// version: https://ia.cr/2026/252) verifies the server message sm and, on
// success, commits the pending ratchet state and counter back into ds. It
// returns acc=false and leaves ds unchanged on failure.
func ClientDone(ds *DeviceState, sm Message) (bool, *DeviceState) {
	// extract fields from ds (line 1)
	rs_cm := ds.rs_cm
	rs_sm := ds.rs_sm
	cnt_cm := ds.cnt_cm
	cnt_sm := ds.cnt_sm

	// extract fields from sm (line 2)
	ct := sm.Ciphertext
	at := sm.AuthTag
	cnt_cm_prime := sm.AD[0]
	cnt_sm_prime := sm.AD[1]

	// FtK on rs_cm (line 3)
	k_sm, rs_sm, cnt_sm := FtK(rs_sm, cnt_sm, cnt_sm_prime)

	// VtD (line 5)
	acc, _ := VtD(k_sm, ct, at, [2]uint32{cnt_cm_prime, cnt_sm_prime})

	// if failure return (line 5)
	if !acc {
		return false, ds
	}

	// Update device state (lines 6 and 7)
	ds.rs_cm = rs_cm
	ds.rs_sm = rs_sm
	ds.cnt_cm = cnt_cm
	ds.cnt_sm = cnt_sm

	// return (line 8)
	return acc, ds
}

// Request (Figure 5 in the proceedings version, Figure 10 in the full version:
// https://ia.cr/2026/252) computes a new commitment to ps and encrypts it into
// a client message, advancing the client ratchet accordingly.  It updates ds
// in place and returns the resulting message.
func Request(ds *DeviceState, ps []byte) (*DeviceState, Message) {
	// extract fields from ds (line 1)
	k_com := ds.k_com
	rs_cm := ds.rs_cm
	cnt_cm := ds.cnt_cm
	cnt_sm := ds.cnt_sm

	// compute commitment (line 2)
	com := PRF(k_com, ps)

	// increment cnt_cm (line 3)
	cnt_cm = cnt_cm + 1

	// KDF (line 4)
	k_cm, rs_cm := KDF(rs_cm)

	// EtM with com as pt (line 5)
	ct, at := EtM(k_cm, com, [2]uint32{cnt_cm, cnt_sm})

	// update ds (line 6)
	ds.rs_cm = rs_cm
	ds.cnt_cm = cnt_cm

	// return (line 7)
	return ds, Message{
		Ciphertext: ct,
		AuthTag:    at,
		AD:         [2]uint32{cnt_cm, ds.cnt_sm},
	}
}

// GetKey (Figure 5 in the proceedings version, Figure 10 in the full version:
// https://ia.cr/2026/252) processes a server message carrying k_1, verifies
// authenticity, and on success reconstructs k = k_0 xor k_1. It updates ds in
// place. On failure it returns acc=false and a nil key, representing \bot in
// the specifications.
func GetKey(ds *DeviceState, sm Message) (bool, *DeviceState, []byte) {
	// extract fields from ds (line 1)
	rs_cm := ds.rs_cm
	rs_sm := ds.rs_sm
	cnt_cm := ds.cnt_cm
	cnt_sm := ds.cnt_sm
	k0 := ds.k0

	// extract fields from sm (line 2)
	ct := sm.Ciphertext
	at := sm.AuthTag
	cnt_cm_prime := sm.AD[0]
	cnt_sm_prime := sm.AD[1]

	// FtK on rs_cm (line 3)
	k_sm, rs_sm, cnt_sm := FtK(rs_sm, cnt_sm, cnt_sm_prime)

	// VtD (line 5)
	acc, pt := VtD(k_sm, ct, at, [2]uint32{cnt_cm_prime, cnt_sm_prime})

	// if failure return (line 5)
	if !acc {
		return false, ds, nil
	}

	// recover key (line 6)
	k := xor(k0, pt)

	// Update device state (lines 7 and 8)
	ds.rs_cm = rs_cm
	ds.rs_sm = rs_sm
	ds.cnt_cm = cnt_cm
	ds.cnt_sm = cnt_sm

	// return on line 9
	return true, ds, k
}

// Clear (Figure 5 in the proceedings version, Figure 10 in the full version:
// https://ia.cr/2026/252) advances the server ratchet locally on the client so
// that old server messages are no longer decryptable and cannot be used to
// reconstruct the session key.
func Clear(ds *DeviceState) *DeviceState {
	// extract fields from ds (line 1)
	rs_sm := ds.rs_sm
	cnt_cm := ds.cnt_cm
	cnt_sm := ds.cnt_sm

	// update device state
	_, ds.rs_sm, ds.cnt_sm = FtK(rs_sm, cnt_sm, cnt_cm)

	return ds
}

// GetCountersClient retruns the counters from the client state.
func GetCountersClient(ds *DeviceState) (uint32, uint32) {
	return ds.cnt_cm, ds.cnt_sm
}
