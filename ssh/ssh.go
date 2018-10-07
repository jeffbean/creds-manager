package ssh

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
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
	KeyType    KeyType
	PrivateKey crypto.PrivateKey
	PublicKey  ssh.PublicKey
}

// GenerateSSHKeyPair creates ssh keys with a passpharse
// TODO: since bitsize is only for some we should use Options pattern
func GenerateSSHKeyPair(kt KeyType, bitSize int) (*KeyPair, error) {
	privateKey, err := generatePrivateKey(kt, bitSize)
	if err != nil {
		return nil, err
	}

	publicKey, err := sshPublic(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create new public key: %v", err)
	}

	return &KeyPair{
		KeyType:    kt,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	}, nil
}

func sshPublic(k crypto.PrivateKey) (ssh.PublicKey, error) {
	return ssh.NewPublicKey(k.(crypto.Signer).Public())
}

func generatePrivateKey(kt KeyType, bitSize int) (crypto.PrivateKey, error) {
	switch kt {
	case RSAPrivateKey:
		rsaKey, err := generateRSAPrivateKey(bitSize)
		if err != nil {
			return nil, fmt.Errorf("failed to create rsa key: %v", err)
		}
		return rsaKey, nil
	case ED25519:
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create ed25519 key: %v", err)
		}
		return &edKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", kt)
	}
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
func marshalED25519PrivateKey(key *ed25519.PrivateKey, comment string) []byte {
	pubKey := key.Public().(ed25519.PublicKey)
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
		Priv:    []byte(*key),
		Comment: comment,
	}

	// Add some padding to match the encryption block size within PrivKeyBlock (without Pad field)
	// the openssh doc says 255 so we just use that i guess
	blockSize := 8
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
