package tlv

import (
	"testing"
	"time"
)

func BenchmarkEncoder_ZeroAlloc(b *testing.B) {
	buf := make([]byte, 1024)
	payload := []byte("benchmark-secret-payload-bytes")
	ts := time.Unix(1700000000, 0)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := NewEncoder(buf)
		if err := enc.WriteTag(1); err != nil {
			b.Fatal(err)
		}
		if err := enc.WriteLength(1); err != nil {
			b.Fatal(err)
		}
		if err := enc.WriteBytes(payload); err != nil {
			b.Fatal(err)
		}
		if err := enc.WriteTime(ts); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecoder_ZeroAlloc(b *testing.B) {
	buf := make([]byte, 1024)
	payload := []byte("benchmark-secret-payload-bytes")
	ts := time.Unix(1700000000, 0)

	enc := NewEncoder(buf)
	if err := enc.WriteTag(1); err != nil {
		b.Fatal(err)
	}
	if err := enc.WriteLength(1); err != nil {
		b.Fatal(err)
	}
	if err := enc.WriteBytes(payload); err != nil {
		b.Fatal(err)
	}
	if err := enc.WriteTime(ts); err != nil {
		b.Fatal(err)
	}
	encoded := buf[:enc.pos]

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dec := NewDecoder(encoded)
		if _, err := dec.ReadTag(); err != nil {
			b.Fatal(err)
		}
		if _, err := dec.ReadLength(); err != nil {
			b.Fatal(err)
		}
		out, err := dec.ReadBytes()
		if err != nil || len(out) != len(payload) {
			b.Fatalf("ReadBytes failed: %v", err)
		}
		if _, err := dec.ReadTime(); err != nil {
			b.Fatal(err)
		}
	}
}
