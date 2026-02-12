package scheme

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Message carries ciphertext, an authentication tag, and the associated-data
// counters cnt_cm and cnt_sm for client messages and server messages,
// respectively.
//
// AD[0] is cnt_cm and AD[1] is cnt_sm.
type Message struct {
	Ciphertext, AuthTag []byte
	AD                  [2]uint32
}

// xor returns the bytewise XOR of a and b up to len(a). It assumes len(a)==len(b).
func xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// PRF computes HMAC-SHA256(key, input) and returns the 32-byte digest.
func PRF(key, input []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return mac.Sum(nil)
}

// KDF expands the given seed using HKDF-SHA256 with a fixed info string and
// returns two 32-byte keys (k1, k2).
func KDF(seed []byte) ([]byte, []byte) {
	h := sha256.New
	hkdfReader := hkdf.New(h, seed, nil, []byte("hkdf-based-kdf"))

	k1 := make([]byte, 32)
	k2 := make([]byte, 32)
	io.ReadFull(hkdfReader, k1)
	io.ReadFull(hkdfReader, k2)

	return k1, k2
}

// EtM (Figure 4) performs Encrypt-then-MAC: it derives (k_enc, k_mac) from key
// k, encrypts pt under k_enc, and authenticates the ciphertext and associated
// counters under k_mac. It panics only if the underlying encryption errors.
func EtM(k, pt []byte, ad [2]uint32) ([]byte, []byte) {
	k_enc, k_mac := KDF(k)
	ct, err := Encrypt(k_enc, pt)
	if err != nil {
		panic(err)
	}

	tag := MAC(k_mac, ct, ad)
	return ct, tag
}

// VtD (Figure 4) performs Verify-then-Decrypt: it derives (k_enc, k_mac) from
// key k, verifies the tag at over (ct, ad), and if valid decrypts ct under
// k_enc to return the plaintext. On failure it returns (false, nil).
func VtD(k, ct, at []byte, ad [2]uint32) (bool, []byte) {
	k_enc, k_mac := KDF(k)
	if !VerifyMAC(k_mac, ct, ad, at) {
		return false, nil
	}
	plaintext, err := Decrypt(k_enc, ct)
	if err != nil {
		return false, nil
	}
	return true, plaintext
}

// Encrypt encrypts a plaintext whose length is a multiple of 16 bytes using
// AES-CBC without padding. The randomly generated IV is prepended to the
// returned ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of block size")
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	// prepend IV
	return append(iv, ciphertext...), nil
}

// Decrypt reverses Encrypt for AES-CBC ciphertexts with a prepended IV and no
// padding. It returns an error if sizes are inconsistent.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

// MAC returns HMAC-SHA256 over ct concatenated with the two counters.
func MAC(key, ct []byte, ad [2]uint32) []byte {
	data := append(ct, byte(ad[0]), byte(ad[1]))
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyMAC compares the expected and provided tags.
func VerifyMAC(key, ct []byte, ad [2]uint32, tag []byte) bool {
	expected := MAC(key, ct, ad)
	return hmac.Equal(expected, tag)
}

// FtK (Figure 4) advances the ratchet position from cnt to cnt_prime.  It
// iteratively applies KDF on rs (if cnt_prime>cnt) and returns the derived key
// for ratchet position cnt_prime, the new seed rs, and the updated counter. If
// cnt_prime<=cnt it returns (nil, rs, cnt) to signal that no forward key is
// available.
func FtK(rs []byte, cnt, cnt_prime uint32) ([]byte, []byte, uint32) {
	k := rs
	if cnt_prime > cnt {
		for i := uint32(0); i < cnt_prime-cnt; i++ {
			k, rs = KDF(rs)
		}

		return k, rs, cnt_prime
	}

	return nil, rs, cnt
}

// RandomKey128 returns a freshly generated 16-byte key.
func RandomKey128() []byte {
	return randomKey(16)
}

// RandomKey256 returns a freshly generated 32-byte key.
func RandomKey256() []byte {
	return randomKey(32)
}

// randomKey returns a freshly generated key of length bytes.
func randomKey(length int) []byte {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		panic("failed to generate random key: " + err.Error())
	}
	return key
}
