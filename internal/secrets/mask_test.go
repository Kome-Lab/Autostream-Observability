package secrets

import "testing"

func TestMaskURL(t *testing.T) {
	got := MaskURL("rtsp://" + "user:" + "secret" + "@example.com/live")
	expected := "rtsp://" + "user:%2A%2A%2A%2A" + "@example.com/live"
	if got != expected {
		t.Fatalf("unexpected masked URL: %s", got)
	}
}
