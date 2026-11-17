package memory

import "testing"

func BenchmarkSecureZero(b *testing.B) {
	buf := make([]byte, 4096)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SecureZero(buf)
	}
}

func BenchmarkSecureCompare(b *testing.B) {
	a := make([]byte, 64)
	c := make([]byte, 64)
	for i := range a {
		a[i] = byte(i)
		c[i] = byte(i)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !SecureCompare(a, c) {
			b.Fatal("expected equal slices")
		}
	}
}

func BenchmarkSecureBufferAccess(b *testing.B) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = 0xAA
	}
	sb, err := NewSecureBufferFromBytes(raw)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = sb.Destroy() }()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := sb.Access(func(pt []byte) error {
			if len(pt) != 64 {
				b.Fatalf("unexpected len: %d", len(pt))
			}
			return nil
		}); err != nil {
			b.Fatal(err)
		}
	}
}
