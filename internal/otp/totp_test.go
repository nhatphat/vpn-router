package otp

import (
	"strings"
	"testing"
	"time"
)

// The RFC 6238 test vector: the ASCII secret "12345678901234567890" in Base32,
// with SHA-1. The published 8-digit codes truncate to these 6-digit ones.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestCodeMatchesTheRFCVectors(t *testing.T) {
	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	}

	for unix, want := range cases {
		got, err := Code(rfcSecret, time.Unix(unix, 0))
		if err != nil {
			t.Fatalf("Code at %d: %v", unix, err)
		}
		if got != want {
			t.Errorf("Code at %d = %s, want %s", unix, got, want)
		}
	}
}

// TestDecodeSecretAcceptsWhatPeoplePaste covers the forms a setup page hands
// out: spaced groups, lowercase, missing padding.
func TestDecodeSecretAcceptsWhatPeoplePaste(t *testing.T) {
	forms := []string{
		rfcSecret,
		strings.ToLower(rfcSecret),
		"gezd gnbv gy3t qojq gezd gnbv gy3t qojq",
		"GEZD-GNBV-GY3T-QOJQ-GEZD-GNBV-GY3T-QOJQ",
	}

	want, err := Code(rfcSecret, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}

	for _, form := range forms {
		got, err := Code(form, time.Unix(59, 0))
		if err != nil {
			t.Errorf("Code(%q): %v", form, err)
			continue
		}
		if got != want {
			t.Errorf("Code(%q) = %s, want %s", form, got, want)
		}
	}
}

// TestDecodeSecretPadsShortSecrets covers a secret whose length is not a
// multiple of eight, which is what most sites display.
func TestDecodeSecretPadsShortSecrets(t *testing.T) {
	if _, err := DecodeSecret("JBSWY3DPEHPK3PXP"); err != nil {
		t.Errorf("a 16-character secret was rejected: %v", err)
	}
	if _, err := DecodeSecret("JBSWY3DP"); err != nil {
		t.Errorf("an 8-character secret was rejected: %v", err)
	}
}

func TestDecodeSecretRejectsRubbish(t *testing.T) {
	for _, bad := range []string{"", "   ", "not base32!", "1234567890"} {
		if _, err := DecodeSecret(bad); err == nil {
			t.Errorf("DecodeSecret(%q) accepted it", bad)
		}
	}
}

func TestSecondsRemaining(t *testing.T) {
	// A code minted exactly on a period boundary has the whole period left.
	if got := SecondsRemaining(time.Unix(1800, 0)); got != 30 {
		t.Errorf("SecondsRemaining at a boundary = %d, want 30", got)
	}
	if got := SecondsRemaining(time.Unix(1829, 0)); got != 1 {
		t.Errorf("SecondsRemaining one second before = %d, want 1", got)
	}
}
