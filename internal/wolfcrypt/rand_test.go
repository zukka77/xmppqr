package wolfcrypt

import "testing"

func TestRead(t *testing.T) {
	b := make([]byte, 32)
	n, err := Read(b)
	if err != nil {
		t.Fatal(err)
	}
	if n != 32 {
		t.Fatalf("got %d bytes", n)
	}
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("all bytes are zero")
	}
}
