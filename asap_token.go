package asap

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"bitbucket.org/atlassian/go-asap"
	"github.com/SermoDigital/jose/crypto"
	"github.com/vincent-petithory/dataurl"
)

// ASAPTokenConfig is used to configure ASAP token generation.
type ASAPTokenConfig struct {
	PrivateKey string        `description:"RSA private key to use when signing tokens."`
	KID        string        `description:"JWT kid value to include in tokens."`
	TTL        time.Duration `description:"Lifetime of a token."`
	Issuer     string        `description:"JWT issuer value to include in tokens."`
	Audiences  []string      `description:"JWT audience values to include in tokens."`
}

// Name of the config root.
func (c *ASAPTokenConfig) Name() string {
	return "asaptoken"
}

// ASAPTokenComponent is an ASAP decorator plugin.
type ASAPTokenComponent struct{}

// ASAPToken satisfies the NewComponent signature.
func ASAPToken(_ context.Context, _ string, _ string, _ string) (interface{}, error) {
	return &ASAPTokenComponent{}, nil
}

// Settings generates a config populated with defaults.
func (m *ASAPTokenComponent) Settings() *ASAPTokenConfig {
	return &ASAPTokenConfig{}
}

// New generates the middleware.
func (*ASAPTokenComponent) New(ctx context.Context, conf *ASAPTokenConfig) (func(http.RoundTripper) http.RoundTripper, error) {
	if len(conf.PrivateKey) < 1 {
		return nil, fmt.Errorf("private key value is empty")
	}
	if len(conf.Issuer) < 1 {
		return nil, fmt.Errorf("issuer value is empty")
	}
	if len(conf.Audiences) < 1 {
		return nil, fmt.Errorf("audience list is empty")
	}
	if len(conf.KID) < 1 {
		return nil, fmt.Errorf("kid value is empty")
	}
	rawKey := conf.PrivateKey
	if strings.HasPrefix(rawKey, "data:") {
		url, _ := dataurl.DecodeString(rawKey)
		rawKey = string(url.Data)
	}
	privateKey, err := asap.NewPrivateKey([]byte(rawKey))
	if err != nil {
		return nil, err
	}
	return asap.NewTransportDecorator(
		asap.NewCachingProvisioner(
			asap.NewProvisioner(conf.KID, conf.TTL, conf.Issuer, conf.Audiences, crypto.SigningMethodRS256),
		),
		privateKey,
	), nil
}
