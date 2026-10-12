package hytale

import "testing"

func TestParseConsoleLineAuthPrompts(t *testing.T) {
	tests := []struct {
		name string
		line string
		url  string
		code string
	}{
		{"single line", "Visit https://accounts.hytale.com/device and enter code: ABCD-1234", "https://accounts.hytale.com/device", "ABCD-1234"},
		{"url alone", "Visit: https://accounts.hytale.com/device", "https://accounts.hytale.com/device", ""},
		{"code alone", "Enter code: ABCD-1234", "", "ABCD-1234"},
		{"url with user_code", "Or visit: https://accounts.hytale.com/device?user_code=ABCD-1234", "https://accounts.hytale.com/device?user_code=ABCD-1234", "ABCD-1234"},
		{"downloader url", "https://oauth.accounts.hytale.com/oauth2/device/verify?user_code=y6CiAccs", "https://oauth.accounts.hytale.com/oauth2/device/verify?user_code=y6CiAccs", "y6CiAccs"},
		{"authorization code", "Authorization code: UCsd9vaU", "", "UCsd9vaU"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := ParseConsoleLine(tt.line)
			if event == nil || event.Type != EventAuthPrompt {
				t.Fatalf("expected auth prompt, got %+v", event)
			}
			if event.URL != tt.url || event.Code != tt.code {
				t.Errorf("got url=%q code=%q, want url=%q code=%q", event.URL, event.Code, tt.url, tt.code)
			}
		})
	}
}

func TestParseConsoleLineIgnoresNonAuthLines(t *testing.T) {
	lines := []string{
		"[HytaleServer] Registered BuilderCodec for com.hypixel.hytale.Item",
		"Failed to decode entity using CodecRegistry",
		"Download it from: https://downloader.hytale.com/hytale-downloader.zip",
		"A new version of hytale-downloader is available: 2026.01.31-abc1234 (current: 2026.01.15-def5678)",
		"See https://hytale.com/news for details",
		"Waiting for authorization (expires in 900 seconds)...",
		"DEVICE AUTHORIZATION",
	}

	for _, line := range lines {
		if event := ParseConsoleLine(line); event != nil && event.Type == EventAuthPrompt {
			t.Errorf("unexpected auth prompt for %q: %+v", line, event)
		}
	}
}

func TestAuthPromptTrackerServerManualFormat(t *testing.T) {
	lines := []string{
		"===================================================================",
		"DEVICE AUTHORIZATION",
		"===================================================================",
		"Visit: https://accounts.hytale.com/device",
		"Enter code: ABCD-1234",
		"Or visit: https://accounts.hytale.com/device?user_code=ABCD-1234",
		"===================================================================",
		"Waiting for authorization (expires in 900 seconds)...",
	}

	tracker := &AuthPromptTracker{}
	var events []*ConsoleEvent
	for _, line := range lines {
		if event := tracker.ProcessLine(line); event != nil && event.Type == EventAuthPrompt {
			events = append(events, event)
		}
	}

	if len(events) == 0 {
		t.Fatal("expected an auth prompt event")
	}
	for _, event := range events {
		if event.Code != "ABCD-1234" || event.URL == "" {
			t.Errorf("unexpected event %+v", event)
		}
	}
}

func TestAuthPromptTrackerIgnoresCodecNoise(t *testing.T) {
	tracker := &AuthPromptTracker{}
	lines := []string{
		"Registered BuilderCodec for com.hypixel.hytale.Item",
		"Download it from: https://downloader.hytale.com/hytale-downloader.zip",
		"Visit: https://accounts.hytale.com/device",
	}
	for _, line := range lines {
		if event := tracker.ProcessLine(line); event != nil && event.Type == EventAuthPrompt {
			t.Fatalf("emitted auth prompt before a real code was printed: %+v", event)
		}
	}

	event := tracker.ProcessLine("Enter code: WXYZ-9876")
	if event == nil || event.Code != "WXYZ-9876" || event.URL != "https://accounts.hytale.com/device" {
		t.Fatalf("expected complete auth prompt, got %+v", event)
	}
}

func TestAuthPromptTrackerExpiresStalePartials(t *testing.T) {
	tracker := &AuthPromptTracker{}
	tracker.ProcessLine("Error code: 5003")
	for i := 0; i < authPromptMaxGap+1; i++ {
		tracker.ProcessLine("some unrelated output")
	}
	if event := tracker.ProcessLine("Visit: https://accounts.hytale.com/device"); event != nil {
		t.Fatalf("stale code was paired with a new URL: %+v", event)
	}
}
