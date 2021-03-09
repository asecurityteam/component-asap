package asap

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/vincent-petithory/dataurl"
)

const (
	validToken = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` //nolint
)

const (
	aud = "testAudience"
	iss = "testIssuer"
)

const (
	kid      = "testKid"
	tokenTTL = time.Hour
)

func TestASAPTokenComponent_New(t *testing.T) {
	pkBytes, _ := rsa.GenerateKey(rand.Reader, 2048)
	pkBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(pkBytes),
	}
	pk := pem.EncodeToMemory(pkBlock)
	dataURIPK := dataurl.EncodeBytes(pk)
	tests := []struct {
		name    string
		conf    *ASAPTokenConfig
		wantErr bool
	}{
		{
			name: "missing or empty PK",
			conf: &ASAPTokenConfig{
				KID:       kid,
				TTL:       tokenTTL,
				Issuer:    iss,
				Audiences: []string{aud},
			},
			wantErr: true,
		},
		{
			name: "missing or empty KID",
			conf: &ASAPTokenConfig{
				PrivateKey: string(pk),
				TTL:        tokenTTL,
				Issuer:     iss,
				Audiences:  []string{aud},
			},
			wantErr: true,
		},
		{
			name: "missing or empty issuer",
			conf: &ASAPTokenConfig{
				PrivateKey: string(pk),
				KID:        kid,
				TTL:        tokenTTL,
				Audiences:  []string{aud},
			},
			wantErr: true,
		},
		{
			name: "missing or empty audiences",
			conf: &ASAPTokenConfig{
				PrivateKey: string(pk),
				KID:        kid,
				TTL:        tokenTTL,
				Issuer:     iss,
			},
			wantErr: true,
		},
		{
			name: "success",
			conf: &ASAPTokenConfig{
				PrivateKey: string(pk),
				KID:        kid,
				TTL:        tokenTTL,
				Issuer:     iss,
				Audiences:  []string{aud},
			},
			wantErr: false,
		},
		{
			name: "success-data-uri",
			conf: &ASAPTokenConfig{
				PrivateKey: dataURIPK,
				KID:        kid,
				TTL:        tokenTTL,
				Issuer:     iss,
				Audiences:  []string{aud},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ASAPTokenComponent{}
			_, err := a.New(context.Background(), tt.conf)
			if (err != nil) != tt.wantErr {
				t.Errorf("ASAPTokenComponent.New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
