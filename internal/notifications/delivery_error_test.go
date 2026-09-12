package notifications

import (
	"errors"
	"testing"
)

func TestSanitizeChannelDeliveryErrorPreservesOnlySafeEmailCodes(t *testing.T) {
	for _, code := range []string{"smtp_auth_failed", "missing_service_scope", "secret_encryption_key_required"} {
		if got := SanitizeChannelDeliveryError("email", errors.New(code)); got != code {
			t.Fatalf("safe email code %q was not preserved: %q", code, got)
		}
	}
	if got := SanitizeChannelDeliveryError("email", errors.New("smtp.internal.example raw-secret")); got != "send_failed" {
		t.Fatalf("unsafe email error was exposed: %q", got)
	}
}
