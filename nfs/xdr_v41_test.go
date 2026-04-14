package nfs

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/smallfz/libnfs-go/xdr"
)

// roundTrip encodes src via xdr.WriteAny and decodes into dst (which must be a
// pointer). The reflection-based xdr package treats a nil slice as "skip" on
// encode but always reads a length prefix on decode, so all slice fields must
// be non-nil (use empty slices) for round-tripping to succeed.
func roundTrip(t *testing.T, src, dst interface{}) {
	t.Helper()
	var buf bytes.Buffer
	w := xdr.NewWriter(&buf)
	if _, err := w.WriteAny(src); err != nil {
		t.Fatalf("WriteAny: %v", err)
	}
	r := xdr.NewReader(&buf)
	if _, err := r.ReadAs(dst); err != nil {
		t.Fatalf("ReadAs: %v", err)
	}
}

func sampleChannelAttrs() ChannelAttrs4 {
	return ChannelAttrs4{
		HeaderPadSize:         0,
		MaxRequestSize:        1048576,
		MaxResponseSize:       1048576,
		MaxResponseSizeCached: 4096,
		MaxOperations:         16,
		MaxRequests:           1,
		RdmaIrd:               []uint32{},
	}
}

func TestRoundTripCreateSession4Args(t *testing.T) {
	src := &CREATE_SESSION4args{
		ClientId:        0xdeadbeefcafef00d,
		Sequence:        7,
		Flags:           0x1,
		ForeChanAttrs:   sampleChannelAttrs(),
		BackChanAttrs:   sampleChannelAttrs(),
		CallbackProgram: 0x40000000,
	}
	dst := &CREATE_SESSION4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("round-trip mismatch\nsrc=%+v\ndst=%+v", src, dst)
	}
}

func TestRoundTripSequence4Args(t *testing.T) {
	src := &SEQUENCE4args{
		SessionId:     [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SequenceId:    42,
		SlotId:        0,
		HighestSlotId: 0,
		CacheThis:     true,
	}
	dst := &SEQUENCE4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("round-trip mismatch\nsrc=%+v\ndst=%+v", src, dst)
	}
}

func TestRoundTripSequence4Resok(t *testing.T) {
	src := &SEQUENCE4resok{
		SessionId:           [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		SequenceId:          43,
		SlotId:              0,
		HighestSlotId:       0,
		TargetHighestSlotId: 0,
		StatusFlags:         0,
	}
	dst := &SEQUENCE4resok{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("round-trip mismatch\nsrc=%+v\ndst=%+v", src, dst)
	}
}

func TestRoundTripDestroySession4Args(t *testing.T) {
	src := &DESTROY_SESSION4args{
		SessionId: [16]byte{9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0, 0, 0, 0, 0, 0},
	}
	dst := &DESTROY_SESSION4args{}
	roundTrip(t, src, dst)
	if !reflect.DeepEqual(src, dst) {
		t.Fatalf("round-trip mismatch\nsrc=%+v\ndst=%+v", src, dst)
	}
}
