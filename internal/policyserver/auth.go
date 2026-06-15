package policyserver

import (
	"time"

	"github.com/yasindce1998/warmor/internal/crypto"
)

type jwtIssuer struct {
	inner *crypto.JWTIssuer
}

func newJWTIssuerFromSecret(secret []byte) *jwtIssuer {
	return &jwtIssuer{inner: crypto.NewJWTIssuer(secret)}
}

func (j *jwtIssuer) Issue(subject, role string, ttl time.Duration) (string, error) {
	return j.inner.Issue(subject, role, ttl)
}

func (j *jwtIssuer) Validate(token string) (*crypto.JWTClaims, error) {
	return j.inner.Validate(token)
}
