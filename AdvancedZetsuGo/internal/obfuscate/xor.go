//go:build windows && amd64

package obfuscate

// XORStr hides literals in the binary; it decrypts into a stack slice.
func XORStr(s string) []byte {
	key := byte(len(s)*13 ^ 0xA5)
	out := make([]byte, len(s)+1) // include null-terminator
	for i := 0; i < len(s); i++ {
		out[i] = s[i] ^ key
	}
	out[len(s)] = 0
	for i := 0; i < len(s); i++ {
		out[i] ^= key
	}
	return out
}

