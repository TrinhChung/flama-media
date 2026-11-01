package config

import "testing"

func TestConfigurationFailsClosedWithoutSecrets(t *testing.T) {
	t.Setenv("MEDIA_SHARED_SECRET", "")
	t.Setenv("GATEWAY_SECRET", "")
	t.Setenv("INTERNAL_SECURITY_SECRET", "")
	t.Setenv("STROKE_ROLE", "disabled")
	if err := Load().Validate(); err == nil {
		t.Fatal("missing secrets accepted")
	}
	t.Setenv("INTERNAL_SECURITY_SECRET", "internal")
	t.Setenv("STROKE_ROLE", "receiver")
	if err := Load().Validate(); err != nil {
		t.Fatalf("receiver should not require public upload credentials: %v", err)
	}
}

func TestDefaultStageTTLIsOneDayAndCORSWildcardRejected(t *testing.T) {
	t.Setenv("MEDIA_SHARED_SECRET", "upload")
	t.Setenv("GATEWAY_SECRET", "gateway")
	t.Setenv("INTERNAL_SECURITY_SECRET", "internal")
	t.Setenv("STROKE_ROLE", "disabled")
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.test")
	t.Setenv("MEDIA_STAGE_TTL_SECONDS", "")
	cfg := Load()
	if cfg.StageTTLSeconds != 86400 {
		t.Fatal("stage TTL is not one day")
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	cfg.AllowedOrigins = "*"
	if err := cfg.Validate(); err == nil {
		t.Fatal("CORS wildcard accepted")
	}
}
