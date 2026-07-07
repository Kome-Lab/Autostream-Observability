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

func TestRawTokenVerifierKeepsLegacyAllScopeBehaviorForTests(t *testing.T) {
	verifier := NewVerifierFromRawTokens("admin-token")
	authenticated, authorized := verifier.AuthorizeToken("admin-token", "remediation.execute")
	if !authenticated || !authorized {
		t.Fatal("explicit raw-token verifier should preserve legacy all-scope behavior")
	}
}

func TestWithRawTokenScopesAddsNodeRuntimeTokenWithWildcardScope(t *testing.T) {
	verifier := WithRawTokenScopes(Verifier{}, "node-runtime-token", "*")
	for _, scope := range []string{"observability.read", "observability.ingest", "remediation.execute"} {
		authenticated, authorized := verifier.AuthorizeToken("node-runtime-token", scope)
		if !authenticated || !authorized {
			t.Fatalf("node runtime token should authorize %s", scope)
		}
	}
}

func TestWithRawTokenScopesCanLimitScopes(t *testing.T) {
	verifier := WithRawTokenScopes(Verifier{}, "read-token", "observability.read")
	authenticated, authorized := verifier.AuthorizeToken("read-token", "observability.read")
	if !authenticated || !authorized {
		t.Fatal("read scope should be authorized")
	}
	authenticated, authorized = verifier.AuthorizeToken("read-token", "remediation.execute")
	if !authenticated || authorized {
		t.Fatal("token without remediation scope must be denied remediation.execute")
	}
}
