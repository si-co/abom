package scheme

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEtMAndVtD(t *testing.T) {
	// --- Setup ---
	key := RandomKey128()

	for _, plaintext := range [][]byte{[]byte("0123456789ABCDEF0123456789ABCDEF"), []byte("0123456789123456")} {
		ad := [2]uint32{1, 2}

		// --- Encrypt then MAC ---
		ct, tag := EtM(key, plaintext, ad)
		require.NotEmpty(t, ct, "ciphertext should not be empty")
		require.NotEmpty(t, tag, "auth tag should not be empty")

		// --- Verify then Decrypt ---
		valid, pt := VtD(key, ct, tag, ad)
		require.True(t, valid, "VtD should return true for valid input")
		require.Equal(t, plaintext, pt, "decrypted plaintext should match original")
	}
}
