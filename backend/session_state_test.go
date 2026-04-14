package backend

import (
	"testing"
)

func TestExchangeIdSameOwnerVerifierReturnsSameClient(t *testing.T) {
	r := NewSessionRegistry()
	owner := []byte("client-A")
	verif := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}

	c1, reused1 := r.ExchangeId(owner, verif)
	if reused1 {
		t.Fatalf("first ExchangeId should not be reuse")
	}
	c2, reused2 := r.ExchangeId(owner, verif)
	if !reused2 {
		t.Fatalf("second ExchangeId with same owner+verifier should reuse")
	}
	if c1.Id != c2.Id {
		t.Fatalf("expected same clientid, got %d vs %d", c1.Id, c2.Id)
	}
}

func TestExchangeIdDifferentOwnerDifferentClient(t *testing.T) {
	r := NewSessionRegistry()
	v := [8]byte{9}
	a, _ := r.ExchangeId([]byte("A"), v)
	b, _ := r.ExchangeId([]byte("B"), v)
	if a.Id == b.Id {
		t.Fatalf("distinct owners should get distinct clientids")
	}
}

func TestExchangeIdRebootDropsSessions(t *testing.T) {
	r := NewSessionRegistry()
	owner := []byte("rebooter")
	v1 := [8]byte{1}
	v2 := [8]byte{2}

	c1, _ := r.ExchangeId(owner, v1)
	if err := r.ConfirmClient(c1.Id); err != nil {
		t.Fatal(err)
	}
	sess, err := r.CreateSession(c1.Id, ChannelAttrs{}, ChannelAttrs{})
	if err != nil {
		t.Fatal(err)
	}

	c2, reused := r.ExchangeId(owner, v2)
	if reused {
		t.Fatalf("verifier change should not be a reuse")
	}
	if c2.Id == c1.Id {
		t.Fatalf("reboot must allocate a new clientid")
	}
	if _, ok := r.LookupSession(sess.Id); ok {
		t.Fatalf("old session should have been dropped on client reboot")
	}
}

func TestCreateSessionBeforeConfirmFails(t *testing.T) {
	r := NewSessionRegistry()
	c, _ := r.ExchangeId([]byte("X"), [8]byte{})
	if _, err := r.CreateSession(c.Id, ChannelAttrs{}, ChannelAttrs{}); err == nil {
		t.Fatalf("expected error creating session before confirm")
	}
}

func TestCreateSessionAfterConfirmHasOneSlot(t *testing.T) {
	r := NewSessionRegistry()
	c, _ := r.ExchangeId([]byte("Y"), [8]byte{})
	if err := r.ConfirmClient(c.Id); err != nil {
		t.Fatal(err)
	}
	s, err := r.CreateSession(c.Id, ChannelAttrs{}, ChannelAttrs{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Slots) != 1 {
		t.Fatalf("want 1 slot, got %d", len(s.Slots))
	}
}

func TestLookupSessionRoundTrip(t *testing.T) {
	r := NewSessionRegistry()
	c, _ := r.ExchangeId([]byte("Z"), [8]byte{})
	_ = r.ConfirmClient(c.Id)
	s, _ := r.CreateSession(c.Id, ChannelAttrs{}, ChannelAttrs{})
	got, ok := r.LookupSession(s.Id)
	if !ok || got.Id != s.Id {
		t.Fatalf("lookup round-trip failed")
	}
}

func TestDestroySessionIdempotent(t *testing.T) {
	r := NewSessionRegistry()
	c, _ := r.ExchangeId([]byte("Q"), [8]byte{})
	_ = r.ConfirmClient(c.Id)
	s, _ := r.CreateSession(c.Id, ChannelAttrs{}, ChannelAttrs{})

	if err := r.DestroySession(s.Id); err != nil {
		t.Fatal(err)
	}
	if err := r.DestroySession(s.Id); err != nil {
		t.Fatalf("second destroy should be idempotent: %v", err)
	}
	if _, ok := r.LookupSession(s.Id); ok {
		t.Fatalf("session should be gone")
	}
}

func TestDestroyClientCascades(t *testing.T) {
	r := NewSessionRegistry()
	c, _ := r.ExchangeId([]byte("Casc"), [8]byte{})
	_ = r.ConfirmClient(c.Id)
	s1, _ := r.CreateSession(c.Id, ChannelAttrs{}, ChannelAttrs{})
	s2, _ := r.CreateSession(c.Id, ChannelAttrs{}, ChannelAttrs{})

	if err := r.DestroyClient(c.Id); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.LookupSession(s1.Id); ok {
		t.Fatalf("s1 should be cascaded out")
	}
	if _, ok := r.LookupSession(s2.Id); ok {
		t.Fatalf("s2 should be cascaded out")
	}
	if err := r.DestroyClient(c.Id); err != nil {
		t.Fatalf("destroy client should be idempotent: %v", err)
	}
}
