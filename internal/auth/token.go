package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"os"
	"strings"
)

type Verifier struct {
	TokenHashes          []string
	TokenSubjects        map[string]Subject
	TokenScopes          map[string]map[string]bool
	BindingRequired      bool
	BindingConfigInvalid bool
	ScopeBindingRequired bool
}

type Subject struct {
	ServiceType string
	ServiceID   string
}

func VerifierFromEnv() Verifier {
	return IngestVerifierFromEnv()
}

func IngestVerifierFromEnv() Verifier {
	raw := os.Getenv("OBSERVABILITY_INGEST_TOKEN_SHA256")
	if raw == "" {
		raw = os.Getenv("OBSERVABILITY_INGEST_TOKEN_SHA256_LIST")
	}
	hashes := splitCSV(raw)
	rawBindings := os.Getenv("OBSERVABILITY_INGEST_TOKEN_BINDINGS")
	bindings, bindingsValid := parseBindings(rawBindings)
	for hash := range bindings {
		if !containsHash(hashes, hash) {
			hashes = append(hashes, hash)
		}
	}
	bindingRequired := envBool("OBSERVABILITY_REQUIRE_INGEST_TOKEN_BINDINGS", true)
	return Verifier{
		TokenHashes:          hashes,
		TokenSubjects:        bindings,
		BindingRequired:      bindingRequired,
		BindingConfigInvalid: bindingRequired && (!bindingsValid || !allHashesBound(hashes, bindings)),
	}
}

func AdminVerifierFromEnv() Verifier {
	raw := os.Getenv("OBSERVABILITY_ADMIN_TOKEN_SHA256")
	if raw == "" {
		raw = os.Getenv("OBSERVABILITY_ADMIN_TOKEN_SHA256_LIST")
	}
	hashes := splitCSV(raw)
	rawBindings := os.Getenv("OBSERVABILITY_ADMIN_TOKEN_BINDINGS")
	scopes := parseScopeBindings(rawBindings)
	for hash := range scopes {
		if !containsHash(hashes, hash) {
			hashes = append(hashes, hash)
		}
	}
	return Verifier{
		TokenHashes:          hashes,
		TokenScopes:          scopes,
		ScopeBindingRequired: envBool("OBSERVABILITY_REQUIRE_ADMIN_TOKEN_BINDINGS", true),
	}
}

func NewVerifierFromRawTokens(tokens ...string) Verifier {
	hashes := make([]string, 0, len(tokens))
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		if token != "" {
			hashes = append(hashes, HashToken(token))
		}
	}
	return Verifier{TokenHashes: hashes}
}

func NewVerifierWithSubjects(subjects map[string]Subject, tokens ...string) Verifier {
	verifier := NewVerifierFromRawTokens(tokens...)
	verifier.TokenSubjects = map[string]Subject{}
	for token, subject := range subjects {
		token = strings.TrimSpace(token)
		if token == "" || strings.TrimSpace(subject.ServiceID) == "" || strings.TrimSpace(subject.ServiceType) == "" {
			continue
		}
		verifier.TokenSubjects[HashToken(token)] = Subject{
			ServiceType: strings.TrimSpace(subject.ServiceType),
			ServiceID:   strings.TrimSpace(subject.ServiceID),
		}
	}
	verifier.BindingRequired = len(verifier.TokenSubjects) > 0
	return verifier
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (v Verifier) VerifyRequest(r *http.Request) bool {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return v.VerifyToken(strings.TrimSpace(raw))
}

func (v Verifier) VerifyRequestSubject(r *http.Request) (Subject, bool) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return Subject{}, false
	}
	return v.VerifyTokenSubject(strings.TrimSpace(raw))
}

func (v Verifier) AuthorizeRequest(r *http.Request, scope string) (bool, bool) {
	raw, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false, false
	}
	return v.AuthorizeToken(strings.TrimSpace(raw), scope)
}

func (v Verifier) AuthorizeToken(raw, scope string) (bool, bool) {
	if _, ok := v.VerifyTokenSubject(raw); !ok {
		return false, false
	}
	got := HashToken(raw)
	if scopes, ok := v.TokenScopes[got]; ok {
		return true, scopes["*"] || scopes[scope]
	}
	if v.ScopeBindingRequired {
		return true, false
	}
	return true, true
}

func (v Verifier) VerifyToken(raw string) bool {
	_, ok := v.VerifyTokenSubject(raw)
	return ok
}

func (v Verifier) VerifyTokenSubject(raw string) (Subject, bool) {
	if v.BindingConfigInvalid {
		return Subject{}, false
	}
	if raw == "" || len(v.TokenHashes) == 0 {
		if len(v.TokenSubjects) == 0 {
			return Subject{}, false
		}
	}
	got := HashToken(raw)
	if subject, ok := v.TokenSubjects[got]; ok {
		return subject, true
	}
	if _, ok := v.TokenScopes[got]; ok {
		return Subject{}, true
	}
	if v.BindingRequired {
		return Subject{}, false
	}
	for _, expected := range v.TokenHashes {
		if subtle.ConstantTimeCompare([]byte(got), []byte(strings.ToLower(expected))) == 1 {
			return Subject{}, true
		}
	}
	return Subject{}, false
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, strings.ToLower(part))
		}
	}
	return out
}

func parseBindings(raw string) (map[string]Subject, bool) {
	out := map[string]Subject{}
	if strings.TrimSpace(raw) == "" {
		return out, true
	}
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			return out, false
		}
		parts := strings.Split(item, ":")
		if len(parts) != 3 {
			return out, false
		}
		hash := strings.ToLower(strings.TrimSpace(parts[0]))
		serviceType := strings.TrimSpace(parts[1])
		serviceID := strings.TrimSpace(parts[2])
		if !validTokenHash(hash) || serviceType == "" || serviceID == "" {
			return out, false
		}
		if _, exists := out[hash]; exists {
			return out, false
		}
		out[hash] = Subject{ServiceType: serviceType, ServiceID: serviceID}
	}
	return out, true
}

func allHashesBound(hashes []string, bindings map[string]Subject) bool {
	for _, hash := range hashes {
		if !validTokenHash(hash) {
			return false
		}
		if _, ok := bindings[strings.ToLower(hash)]; !ok {
			return false
		}
	}
	return true
}

func validTokenHash(hash string) bool {
	decoded, err := hex.DecodeString(hash)
	return err == nil && len(decoded) == sha256.Size
}

func parseScopeBindings(raw string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), ":", 2)
		if len(parts) != 2 {
			continue
		}
		hash := strings.ToLower(strings.TrimSpace(parts[0]))
		if len(hash) != 64 {
			continue
		}
		scopes := map[string]bool{}
		for _, scope := range strings.Split(parts[1], "|") {
			scope = strings.TrimSpace(scope)
			if scope != "" {
				scopes[scope] = true
			}
		}
		if len(scopes) > 0 {
			out[hash] = scopes
		}
	}
	return out
}

func containsHash(hashes []string, target string) bool {
	for _, hash := range hashes {
		if strings.EqualFold(hash, target) {
			return true
		}
	}
	return false
}

func envBool(name string, fallback bool) bool {
	value, ok := os.LookupEnv(name)
	if !ok {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
