package nfs

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/smallfz/libnfs-go/xdr"
)

func TestRoundTripSEEK4args(t *testing.T) {
	src := &SEEK4args{
		StateId: StateId4{SeqId: 3, Other: [3]uint32{0xabc, 0, 0}},
		Offset:  1 << 20,
		What:    NFS4_CONTENT_HOLE,
	}
	dst := &SEEK4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("SEEK4args round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestRoundTripSEEK4resok(t *testing.T) {
	src := &SEEK4resok{Eof: true, Offset: 4096}
	dst := &SEEK4resok{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("SEEK4resok round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestRoundTripCOPY4args(t *testing.T) {
	src := &COPY4args{
		SrcStateId:  StateId4{SeqId: 1, Other: [3]uint32{0x11, 0, 0}},
		DstStateId:  StateId4{SeqId: 2, Other: [3]uint32{0x22, 0, 0}},
		SrcOffset:   0,
		DstOffset:   0,
		Count:       0,
		Consecutive: true,
		Synchronous: true,
		SrcServers:  Netloc4List{},
	}
	dst := &COPY4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("COPY4args round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestCOPY4argsRejectsNonEmptySrcServers(t *testing.T) {
	// Hand-craft a COPY4args on the wire where src_servers<> has one entry.
	// The Netloc4List decoder must fail so the reader never walks into the
	// undefined netloc4 union.
	var buf bytes.Buffer
	w := xdr.NewWriter(&buf)
	if _, err := w.WriteAny(&StateId4{SeqId: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteAny(&StateId4{SeqId: 2}); err != nil {
		t.Fatal(err)
	}
	w.WriteAny(uint64(0)) // SrcOffset
	w.WriteAny(uint64(0)) // DstOffset
	w.WriteAny(uint64(0)) // Count
	w.WriteUint32(1)      // Consecutive true
	w.WriteUint32(1)      // Synchronous true
	w.WriteUint32(1)      // src_servers<> length = 1 — illegal

	r := xdr.NewReader(&buf)
	dst := &COPY4args{}
	if _, err := r.ReadAs(dst); err == nil {
		t.Fatalf("expected error on non-empty src_servers, got nil")
	}
}

func TestRoundTripGETXATTR4args(t *testing.T) {
	src := &GETXATTR4args{Name: "user.checksum"}
	dst := &GETXATTR4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("GETXATTR4args round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestRoundTripSETXATTR4args(t *testing.T) {
	src := &SETXATTR4args{
		Option: SETXATTR4_CREATE,
		Name:   "user.foo",
		Value:  []byte("bar-baz"),
	}
	dst := &SETXATTR4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("SETXATTR4args round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestRoundTripLISTXATTRS4args(t *testing.T) {
	src := &LISTXATTRS4args{Cookie: 42, MaxCount: 4096}
	dst := &LISTXATTRS4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("LISTXATTRS4args round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestRoundTripLISTXATTRS4resok(t *testing.T) {
	src := &LISTXATTRS4resok{
		Cookie: 10,
		Names:  []string{"user.a", "user.b", "user.c"},
		Eof:    true,
	}
	dst := &LISTXATTRS4resok{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("LISTXATTRS4resok round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestRoundTripREMOVEXATTR4args(t *testing.T) {
	src := &REMOVEXATTR4args{Name: "user.stale"}
	dst := &REMOVEXATTR4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("REMOVEXATTR4args round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}

func TestRoundTripALLOCATE4args(t *testing.T) {
	src := &ALLOCATE4args{
		StateId: StateId4{SeqId: 5},
		Offset:  1024,
		Length:  8192,
	}
	dst := &ALLOCATE4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("ALLOCATE4args round-trip mismatch:\n src=%+v\n dst=%+v", src, dst)
	}
}
