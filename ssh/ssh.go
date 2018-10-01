package ssh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// PemType is a string type for the Key PEM block.
type PemType string

const (
	// RSAPrivateKey is a RSA private key type
	RSAPrivateKey PemType = "RSA PRIVATE KEY"
)

// KeyPair is a private and public set pf keys intended for creating ssh keys
type KeyPair struct {
	PemType PemType

	PrivateKey crypto.PrivateKey
	PublicKey  ssh.PublicKey
}

// GenerateSSHKeyPair creates ssh keys with a passpharse
func GenerateSSHKeyPair(passphrase string, pt PemType, bitSize int) (*KeyPair, error) {
	privateKey, err := generateRSAPrivateKey(bitSize)
	if err != nil {
		return nil, err
	}

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create new public key: %v", err)
	}

	block := &pem.Block{
		Type:  string(pt),
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt pem block: %v", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		PemType:    pt,
	}, nil
}

func generateRSAPrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, fmt.Errorf("failed creating private key: %v", err)
	}

	if err := privateKey.Validate(); err != nil {
		return nil, fmt.Errorf("failed validation of private key: %v", err)
	}

	return privateKey, nil
}
