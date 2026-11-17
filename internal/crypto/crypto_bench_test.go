package crypto

import "testing"

func BenchmarkEncryptAEADInPlace(b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	aad := []byte("HAKOv001")
	const payloadSize = 4096
	// Allocate once with +16 capacity for the GCM tag; Seal overwrites in place.
	buf := make([]byte, payloadSize, payloadSize+16)
	for i := range payloadSize {
		buf[i] = byte(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ct, err := EncryptAEADInPlace(buf[:payloadSize], nonce, key, aad)
		if err != nil {
			b.Fatal(err)
		}
		if len(ct) != payloadSize+16 {
			b.Fatalf("unexpected ciphertext len: %d", len(ct))
		}
	}
}

func BenchmarkDecryptAEADInPlace(b *testing.B) {
	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	aad := []byte("HAKOv001")
	const payloadSize = 4096
	seed := make([]byte, payloadSize, payloadSize+16)
	for i := range payloadSize {
		seed[i] = byte(i)
	}
	sealed, err := EncryptAEADInPlace(seed[:payloadSize], nonce, key, aad)
	if err != nil {
		b.Fatal(err)
	}
	work := make([]byte, len(sealed))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(work, sealed)
		pt, decErr := DecryptAEADInPlace(work, nonce, key, aad)
		if decErr != nil {
			b.Fatal(decErr)
		}
		if len(pt) != payloadSize {
			b.Fatalf("unexpected plaintext len: %d", len(pt))
		}
	}
}
