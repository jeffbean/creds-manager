package ssh

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func WriteKeysToDirectory(kp *KeyPair, directory string) error {
	privatePath := filepath.Join(directory, "foo.rsa")
	publishPath := privatePath + ".pub"

	privateBytes, err := encodePrivateKeyToPEM(kp.PrivateKey, kp.PemType)
	if err != nil {
		return err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(kp.PublicKey)

	if err := ioutil.WriteFile(privatePath, privateBytes, 0600); err != nil {
		return fmt.Errorf("failed writing private file: %v", err)
	}

	if err := ioutil.WriteFile(publishPath, pubKeyBytes, 0600); err != nil {
		return fmt.Errorf("failed writing public file: %v", err)
	}

	return nil
}

func encodePrivateKeyToPEM(privateKey crypto.PrivateKey, pt KeyType) ([]byte, error) {
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateBlock := pem.Block{
		Type:    string(pt),
		Headers: nil,
		Bytes:   privateDER,
	}

	return pem.EncodeToMemory(&privateBlock), nil
}
