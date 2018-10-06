package ssh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mrand "math/rand"

	"golang.org/x/crypto/ed25519"

	"golang.org/x/crypto/ssh"
)

// KeyType is a string type for the Key PEM block.
type KeyType string

// Key types that are supported for ssh generation.
const (
	RSAPrivateKey KeyType = "RSA PRIVATE KEY"
	ED25519       KeyType = "OPENSSH PRIVATE KEY"
)

// KeyPair is a private and public set pf keys intended for creating ssh keys
type KeyPair struct {
	PemType KeyType

	PrivateKey crypto.Signer
	PublicKey  ssh.PublicKey
}

// GenerateSSHKeyPair creates ssh keys with a passpharse
func GenerateSSHKeyPair(passphrase string, pt KeyType, bitSize int) (*KeyPair, error) {
	signer, privateKeyBytes, err := generatePrivateKey(pt, bitSize)
	if err != nil {
		return nil, err
	}

	publicKey, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("failed to create new public key: %v", err)
	}

	// private := privateKey
	block := &pem.Block{
		Type:  string(pt),
		Bytes: privateKeyBytes,
	}

	block, err = x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt pem block: %v", err)
	}

	return &KeyPair{
		PrivateKey: signer,
		PublicKey:  publicKey,
		PemType:    pt,
	}, nil
}

func generatePrivateKey(kt KeyType, bitSize int) (crypto.Signer, []byte, error) {
	var (
		privateKey      crypto.Signer
		privateKeyBytes []byte
	)
	switch kt {
	case RSAPrivateKey:
		rsaKey, err := generateRSAPrivateKey(bitSize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create rsa key: %v", err)
		}
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(rsaKey)
		privateKey = rsaKey
	case ED25519:
		edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create ed25519 key: %v", err)
		}
		privateKeyBytes = marshalED25519PrivateKey(edPub, edKey)
		privateKey = edKey
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %v", kt)
	}

	return privateKey, privateKeyBytes, nil
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

// Reversed engineered from the golang ssh library: https://github.com/golang/crypto/blob/master/ssh/keys.go#L905
// no guarantees :D
func marshalED25519PrivateKey(pubKey ed25519.PublicKey, key ed25519.PrivateKey) []byte {
	// Per RFC: https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.key
	magic := append([]byte("openssh-key-v1"), 0)

	// the check bits
	check := mrand.Uint32()

	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Pub     []byte
		Priv    []byte
		Comment string
		Pad     []byte `ssh:"rest"`
	}{
		Check1:  check,
		Check2:  check,
		Keytype: ssh.KeyAlgoED25519,
		Pub:     []byte(pubKey),
		Priv:    []byte(key),
		Comment: "",
	}

	// Add some padding to match the encryption block size within PrivKeyBlock (without Pad field)
	// the openssh doc says 255 so we just use that i guess
	blockSize := 255
	blockLen := len(ssh.Marshal(pk1))
	padLen := (blockSize - (blockLen % blockSize)) % blockSize

	// Padding is a sequence of increasing integers: 1, 2, 3...
	pk1.Pad = make([]byte, padLen)
	for i := 1; i < padLen; i++ {
		pk1.Pad[i] = byte(i)
	}

	// Generate the pubkey prefix "\0\0\0\nssh-ed25519\0\0\0 "
	prefix := []byte{0x0, 0x0, 0x0, 0x0b}
	prefix = append(prefix, []byte(ssh.KeyAlgoED25519)...)
	prefix = append(prefix, []byte{0x0, 0x0, 0x0, 0x20}...)

	// Go only handles un-encrypted private blocks for now
	// https://github.com/golang/crypto/blob/master/ssh/keys.go#L925
	w := struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}{
		CipherName:   "none",
		KdfName:      "none",
		KdfOpts:      "",
		NumKeys:      1,
		PubKey:       append(prefix, pubKey...),
		PrivKeyBlock: ssh.Marshal(pk1),
	}
	magic = append(magic, ssh.Marshal(w)...)

	return magic
}
