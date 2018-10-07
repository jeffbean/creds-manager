package ssh

import (
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRSAPrivateKey(t *testing.T) {
	size := 1024
	if testing.Short() {
		size = 128
	}
	priv, err := generateRSAPrivateKey(size)
	require.NoError(t, err)

	testKeyBasics(t, priv)
}

func TestGenerateSSHKeyPair(t *testing.T) {
	tests := []struct {
		msg        string
		passphrase string
		pt         KeyType

		wantErr string
	}{
		{
			msg:        "no passphrase",
			passphrase: "",
			pt:         RSAPrivateKey,
		},
		{
			msg:        "foobar pem type",
			passphrase: "",
			pt:         KeyType("foobar"),
			wantErr:    "unsupported key type: foobar",
		},
		{
			msg:        "passphrase",
			passphrase: "testing",
			pt:         RSAPrivateKey,
		},
		{
			msg:        "ed type",
			passphrase: "testing",
			pt:         ED25519,
		},
		{
			msg:        "no pem type",
			passphrase: "testing",
			wantErr:    "unsupported key type: ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.msg, func(t *testing.T) {
			size := 1024
			if testing.Short() {
				size = 128
			}

			got, err := GenerateSSHKeyPair(tt.pt, size)
			if tt.wantErr != "" {
				assert.EqualError(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			switch got.PrivateKey.(type) {
			case *rsa.PrivateKey:
				testKeyBasics(t, got.PrivateKey.(*rsa.PrivateKey))
			}
		})
	}
}

func testKeyBasics(t *testing.T, priv *rsa.PrivateKey) {
	if err := priv.Validate(); err != nil {
		t.Errorf("Validate() failed: %s", err)
	}
	if priv.D.Cmp(priv.N) > 0 {
		t.Errorf("private exponent too large")
	}
}
