package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
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

func WithRawTokenScopes(verifier Verifier, rawToken string, scopes ...string) Verifier {
	rawToken = strings.TrimSpace(rawToken)
	if rawToken == "" {
		return verifier
	}
	hash := HashToken(rawToken)
	if !containsHash(verifier.TokenHashes, hash) {
		verifier.TokenHashes = append(verifier.TokenHashes, hash)
	}
	if verifier.TokenScopes == nil {
		verifier.TokenScopes = map[string]map[string]bool{}
	}
	if verifier.TokenScopes[hash] == nil {
		verifier.TokenScopes[hash] = map[string]bool{}
	}
	if len(scopes) == 0 {
		scopes = []string{"*"}
	}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope != "" {
			verifier.TokenScopes[hash][scope] = true
		}
	}
	return verifier
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

func containsHash(hashes []string, target string) bool {
	for _, hash := range hashes {
		if strings.EqualFold(hash, target) {
			return true
		}
	}
	return false
}
