package auth

import (
	"net/http"
	"testing"
)

func TestHashTokenAndVerify(t *testing.T) {
	verifier := NewVerifierFromRawTokens("service-token")
	if !verifier.VerifyToken("service-token") {
		t.Fatal("expected token to verify")
	}
	if verifier.VerifyToken("wrong-token") {
		t.Fatal("wrong token must not verify")
	}
}

func TestVerifierFailsClosedWithoutHashes(t *testing.T) {
	if (Verifier{}).VerifyToken("service-token") {
		t.Fatal("empty verifier must fail closed")
	}
}

func TestVerifyRequestRequiresBearer(t *testing.T) {
	verifier := NewVerifierFromRawTokens("service-token")
	req, err := http.NewRequest(http.MethodPost, "/signals", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Basic service-token")
	if verifier.VerifyRequest(req) {
		t.Fatal("non-bearer auth must fail")
	}
	req.Header.Set("Authorization", "Bearer service-token")
	if !verifier.VerifyRequest(req) {
		t.Fatal("bearer token should verify")
	}
}

func TestVerifierFromEnv(t *testing.T) {
	hash := HashToken("service-token")
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_SHA256", hash)
	t.Setenv("OBSERVABILITY_REQUIRE_INGEST_TOKEN_BINDINGS", "false")
	verifier := VerifierFromEnv()
	if !verifier.VerifyToken("service-token") {
		t.Fatal("expected env hash to verify")
	}
}

func TestBoundVerifierReturnsSubjectAndRequiresBoundToken(t *testing.T) {
	verifier := NewVerifierWithSubjects(map[string]Subject{
		"encoder-token": {ServiceType: "encoder_recorder", ServiceID: "enc-01"},
	}, "legacy-token")

	subject, ok := verifier.VerifyTokenSubject("encoder-token")
	if !ok {
		t.Fatal("expected bound token to verify")
	}
	if subject.ServiceType != "encoder_recorder" || subject.ServiceID != "enc-01" {
		t.Fatalf("unexpected subject: %#v", subject)
	}
	if verifier.VerifyToken("legacy-token") {
		t.Fatal("unbound legacy token must fail when bindings are required")
	}
}

func TestIngestVerifierFromEnvSupportsBindings(t *testing.T) {
	hash := HashToken("encoder-token")
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_SHA256", hash)
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_BINDINGS", hash+":encoder_recorder:enc-01")
	verifier := IngestVerifierFromEnv()
	subject, ok := verifier.VerifyTokenSubject("encoder-token")
	if !ok {
		t.Fatal("expected bound env token to verify")
	}
	if subject.ServiceType != "encoder_recorder" || subject.ServiceID != "enc-01" {
		t.Fatalf("unexpected subject: %#v", subject)
	}
}

func TestIngestVerifierFromEnvRequiresBindingsByDefault(t *testing.T) {
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_SHA256", HashToken("service-token"))
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_BINDINGS", "")
	t.Setenv("OBSERVABILITY_REQUIRE_INGEST_TOKEN_BINDINGS", "")

	verifier := IngestVerifierFromEnv()
	if !verifier.BindingRequired {
		t.Fatal("ingest token bindings must be required by default")
	}
	if verifier.VerifyToken("service-token") {
		t.Fatal("token without a binding must fail authentication")
	}
}

func TestIngestVerifierFromEnvRejectsPartialBindings(t *testing.T) {
	encoderHash := HashToken("encoder-token")
	workerHash := HashToken("worker-token")
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_SHA256_LIST", encoderHash+","+workerHash)
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_BINDINGS", encoderHash+":encoder_recorder:enc-01")

	verifier := IngestVerifierFromEnv()
	if verifier.VerifyToken("encoder-token") {
		t.Fatal("partial binding configuration must reject all ingest authentication")
	}
	if verifier.VerifyToken("worker-token") {
		t.Fatal("unbound allowed token must fail authentication")
	}
}

func TestIngestVerifierFromEnvRejectsMalformedBindings(t *testing.T) {
	hash := HashToken("service-token")
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_SHA256", hash)
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_BINDINGS", hash+":worker")

	verifier := IngestVerifierFromEnv()
	if verifier.VerifyToken("service-token") {
		t.Fatal("malformed binding configuration must reject ingest authentication")
	}
}

func TestIngestVerifierFromEnvCanExplicitlyDisableRequiredBindings(t *testing.T) {
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_SHA256", HashToken("shared-dev-token"))
	t.Setenv("OBSERVABILITY_INGEST_TOKEN_BINDINGS", "")
	t.Setenv("OBSERVABILITY_REQUIRE_INGEST_TOKEN_BINDINGS", "false")

	verifier := IngestVerifierFromEnv()
	if verifier.BindingRequired {
		t.Fatal("explicit false must disable required ingest bindings")
	}
	if !verifier.VerifyToken("shared-dev-token") {
		t.Fatal("explicit local-development override should allow the shared token")
	}
}

func TestAdminVerifierFromEnvEnforcesPerTokenScopes(t *testing.T) {
	hash := HashToken("read-token")
	t.Setenv("OBSERVABILITY_ADMIN_TOKEN_SHA256", hash)
	t.Setenv("OBSERVABILITY_ADMIN_TOKEN_BINDINGS", hash+":observability.read|notifications.read")
	t.Setenv("OBSERVABILITY_REQUIRE_ADMIN_TOKEN_BINDINGS", "true")

	verifier := AdminVerifierFromEnv()
	authenticated, authorized := verifier.AuthorizeToken("read-token", "observability.read")
	if !authenticated || !authorized {
		t.Fatal("read scope should be authorized")
	}
	authenticated, authorized = verifier.AuthorizeToken("read-token", "remediation.execute")
	if !authenticated || authorized {
		t.Fatal("valid read-only token must be denied remediation.execute")
	}
}

func TestAdminVerifierFromEnvFailsClosedWithoutRequiredBindings(t *testing.T) {
	t.Setenv("OBSERVABILITY_ADMIN_TOKEN_SHA256", HashToken("legacy-admin-token"))
	t.Setenv("OBSERVABILITY_ADMIN_TOKEN_BINDINGS", "")
	t.Setenv("OBSERVABILITY_REQUIRE_ADMIN_TOKEN_BINDINGS", "true")

	verifier := AdminVerifierFromEnv()
	authenticated, authorized := verifier.AuthorizeToken("legacy-admin-token", "observability.read")
	if !authenticated || authorized {
		t.Fatal("valid legacy token must authenticate but fail authorization without required scope bindings")
	}
}

func TestAdminVerifierFromEnvMalformedBindingDoesNotGrantAllScopes(t *testing.T) {
	t.Setenv("OBSERVABILITY_ADMIN_TOKEN_SHA256", HashToken("legacy-admin-token"))
	t.Setenv("OBSERVABILITY_ADMIN_TOKEN_BINDINGS", "malformed")
	t.Setenv("OBSERVABILITY_REQUIRE_ADMIN_TOKEN_BINDINGS", "true")

	verifier := AdminVerifierFromEnv()
	authenticated, authorized := verifier.AuthorizeToken("legacy-admin-token", "observability.read")
	if !authenticated || authorized {
		t.Fatal("malformed admin binding must fail closed")
	}
}

func TestRawTokenVerifierKeepsLegacyAllScopeBehaviorForTests(t *testing.T) {
	verifier := NewVerifierFromRawTokens("admin-token")
	authenticated, authorized := verifier.AuthorizeToken("admin-token", "remediation.execute")
	if !authenticated || !authorized {
		t.Fatal("explicit raw-token verifier should preserve legacy all-scope behavior")
	}
}
