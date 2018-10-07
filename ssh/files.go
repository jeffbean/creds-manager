package ssh

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

func WriteKeysToDisk(filename string, kp *KeyPair, comment string) error {
	publishPath := filename + ".pub"

	privateBytes, err := EncodeKeyForOpenSSH(kp.KeyType, kp.PrivateKey, comment)
	if err != nil {
		return err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(kp.PublicKey)

	if err := ioutil.WriteFile(filename, privateBytes, 0600); err != nil {
		return fmt.Errorf("failed writing private file: %v", err)
	}
	fmt.Printf("Your identification has been saved in %q\n", filename)

	if err := ioutil.WriteFile(publishPath, pubKeyBytes, 0600); err != nil {
		return fmt.Errorf("failed writing public file: %v", err)
	}
	fmt.Printf("Your public key has been saved in %q\n", publishPath)

	fmt.Println("The key fingerprint is:")
	fmt.Println(ssh.FingerprintSHA256(kp.PublicKey))

	return nil
}

func EncodeKeyForOpenSSH(pemType KeyType, priv crypto.PrivateKey, comment string) ([]byte, error) {
	var (
		privateKeyBytes []byte
		err             error
	)
	switch key := priv.(type) {
	case *rsa.PrivateKey:
		privateKeyBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
	case *ed25519.PrivateKey:
		privateKeyBytes = marshalED25519PrivateKey(key, comment)
	default:
		return nil, fmt.Errorf("key type not supported: %T", key)
	}

	block := &pem.Block{
		Type:    string(pemType),
		Headers: nil,
		Bytes:   privateKeyBytes,
	}

	return pem.EncodeToMemory(block), nil
}
