// Package otp generates the time-based one-time codes the VPN challenges for.
//
// vpnctl does not need to answer that challenge — the container does, with
// oathtool — so this exists for one reason: to check at setup time that the
// secret someone typed is the secret their authenticator has. A wrong secret
// is otherwise indistinguishable from a wrong password, a wrong profile or a
// server problem, and only shows up as a VPN that will not connect.
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Period is the interval every authenticator uses by default.
const Period = 30 * time.Second

// digits in a generated code.
const digits = 6

// DecodeSecret parses a Base32 setup secret the way authenticator apps accept
// it: case-insensitively, with the spaces people paste from a website, and
// with or without padding.
func DecodeSecret(secret string) ([]byte, error) {
	cleaned := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "").Replace(strings.TrimSpace(secret)))
	if cleaned == "" {
		return nil, fmt.Errorf("the secret is empty")
	}

	// Pad to a multiple of 8, which is what the standard encoding expects and
	// what sites usually strip before showing it to you.
	if pad := len(cleaned) % 8; pad != 0 {
		cleaned += strings.Repeat("=", 8-pad)
	}

	key, err := base32.StdEncoding.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("the secret is not valid Base32: %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("the secret decodes to nothing")
	}
	return key, nil
}

// Code returns the code for a moment in time.
func Code(secret string, at time.Time) (string, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}

	counter := uint64(at.Unix()) / uint64(Period.Seconds())

	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation, RFC 4226 section 5.4.
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod), nil
}

// SecondsRemaining is how long the current code stays valid, so a prompt can
// say whether it is worth comparing right now.
func SecondsRemaining(at time.Time) int {
	period := int64(Period.Seconds())
	return int(period - at.Unix()%period)
}
