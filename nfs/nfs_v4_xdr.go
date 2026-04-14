package nfs

import (
	"fmt"

	"github.com/smallfz/libnfs-go/xdr"
)

// XdrUnmarshal decodes state_protect4_a as a discriminated union per RFC 5661
// §18.35. The reflection-based decoder can't handle unions, so this method is
// required for EXCHANGE_ID args to parse on the wire.
func (s *StateProtect4A) XdrUnmarshal(r *xdr.Reader) (int, error) {
	how, err := r.ReadUint32()
	if err != nil {
		return 0, err
	}
	s.How = how
	s.MachOps = nil
	s.SsvParams = nil
	switch how {
	case SP4_NONE:
		return 4, nil
	case SP4_MACH_CRED:
		s.MachOps = &StateProtectOps4{}
		size, err := r.ReadAs(s.MachOps)
		return 4 + size, err
	case SP4_SSV:
		s.SsvParams = &SsvSpParams4{}
		size, err := r.ReadAs(s.SsvParams)
		return 4 + size, err
	default:
		return 4, fmt.Errorf("unknown state_protect_how4 on decode: %d", how)
	}
}

// XdrUnmarshal decodes callback_sec_parms4, a discriminated union keyed on
// cb_secflavor (RFC 5661 §18.36 + RFC 5531). Linux kernel clients send one
// entry per AUTH flavor they're willing to accept for back-channel callbacks.
func (c *CallbackSecParams4) XdrUnmarshal(r *xdr.Reader) (int, error) {
	flavor, err := r.ReadUint32()
	if err != nil {
		return 0, err
	}
	c.CbSecFlavor = flavor
	c.SysCred = nil
	consumed := 4
	switch flavor {
	case AUTH_FLAVOR_NULL:
		return consumed, nil
	case AUTH_FLAVOR_UNIX:
		c.SysCred = &AuthSysParms4{}
		n, err := r.ReadAs(c.SysCred)
		return consumed + n, err
	default:
		// RPCSEC_GSS (6) and other flavors carry a flavor-specific body we
		// do not decode. Consume the length-prefixed opaque body per RFC
		// 5531: <secbody> is encoded as opaque<>. Actually flavors 0..5 have
		// no length prefix, but RPCSEC_GSS wraps handles. Safest minimal
		// approach: return an error so the caller can decide to reject the
		// CREATE_SESSION. Tests show the Linux kernel only sends AUTH_NONE
		// and AUTH_SYS on the callback channel in practice.
		return consumed, fmt.Errorf("unsupported cb_secflavor %d", flavor)
	}
}

// XdrMarshal emits a zero-length netloc4<> list on the wire. Round-
// trips with XdrUnmarshal below; also the only value our COPY handler
// ever produces (we never advertise other servers).
func (n *Netloc4List) XdrMarshal(w *xdr.Writer) (int, error) {
	return w.WriteUint32(0)
}

// XdrUnmarshal decodes the "source servers" list of COPY4args. We only
// implement synchronous intra-server copy (RFC 7862 §15.2.3), so any
// non-empty netloc4<> list is rejected outright — we don't implement
// the netloc4 discriminated union, and accepting one would desync the
// wire.
func (n *Netloc4List) XdrUnmarshal(r *xdr.Reader) (int, error) {
	count, err := r.ReadUint32()
	if err != nil {
		return 0, err
	}
	if count != 0 {
		return 4, fmt.Errorf("COPY4args: non-empty source-servers list (%d) not supported", count)
	}
	return 4, nil
}

// XdrUnmarshal decodes state_protect4_r. Only used if a client calls
// EXCHANGE_ID on us in a direction we support decoding (uncommon — servers
// typically only emit this), but included for symmetry.
func (s *StateProtect4R) XdrUnmarshal(r *xdr.Reader) (int, error) {
	how, err := r.ReadUint32()
	if err != nil {
		return 0, err
	}
	s.How = how
	s.MachOps = nil
	s.SsvInfo = nil
	switch how {
	case SP4_NONE:
		return 4, nil
	case SP4_MACH_CRED:
		s.MachOps = &StateProtectOps4{}
		size, err := r.ReadAs(s.MachOps)
		return 4 + size, err
	case SP4_SSV:
		s.SsvInfo = &SsvProtInfo4{}
		size, err := r.ReadAs(s.SsvInfo)
		return 4 + size, err
	default:
		return 4, fmt.Errorf("unknown state_protect_how4 on decode: %d", how)
	}
}
