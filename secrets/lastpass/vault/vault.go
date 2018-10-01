package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"

	"github.com/jeffbean/creds-manager/secrets"
	"github.com/jeffbean/creds-manager/secrets/lastpass"
)

// TODO: lots to think about in terms of organization and seperation of concerns
// should we decrypt and parse not in the vault.
// this is nice so far since the Blob itself could be loaded from disk or somewhere else.
// but it adds some dependant piece on reading Items that happen in the parsing of the
// blob anyway.

// Vault is the lastpass vault object that has the accounts and notes
// parsed and decrypted into an object.
type Vault struct {
	Cipher   cipher.Block
	Version  uint64
	Accounts []*lastpass.Account
}

// NewVault create a vault based on a lastpass Blob object
// it could be local
func NewVault(blob *lastpass.Blob, encryptionKey []byte) (*Vault, error) {
	cipher, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	accounts, err := parseAccounts(blob.AccountChunks, cipher)
	if err != nil {
		return nil, err
	}

	return &Vault{Version: blob.Version, Cipher: cipher, Accounts: accounts}, nil
}

func (v *Vault) Load(ctx context.Context, name string) *secrets.Secret {
	for _, a := range v.Accounts {
		if a.Name == name {
			return &secrets.Secret{Name: name, Value: a}
		}
	}
	return nil
}

func (v *Vault) Save(ctx context.Context, s *secrets.Secret) error {
	return nil
}

func parseAccounts(accountChunks [][]byte, c cipher.Block) ([]*lastpass.Account, error) {
	accounts := make([]*lastpass.Account, 0)
	for _, accountChunk := range accountChunks {
		acct, err := parseAccount(bytes.NewReader(accountChunk), c)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acct)
	}
	return accounts, nil
}

func parseAccount(reader io.Reader, c cipher.Block) (*lastpass.Account, error) {
	id, err := lastpass.ReadItem(reader)
	if err != nil {
		return nil, err
	}
	name, err := lastpass.ReadItem(reader)
	if err != nil {
		return nil, err
	}
	decryptedName, err := decryptField(name, c)
	if err != nil {
		return nil, err
	}
	// group
	if _, err := lastpass.ReadItem(reader); err != nil {
		return nil, err
	}

	// url
	if _, err := lastpass.ReadItem(reader); err != nil {
		return nil, err
	}

	// notes
	if _, err := lastpass.ReadItem(reader); err != nil {
		return nil, err
	}

	for i := 0; i < 2; i++ {
		// skips
		if _, err := lastpass.ReadItem(reader); err != nil {
			return nil, err
		}
	}

	username, err := lastpass.ReadItem(reader)
	if err != nil {
		return nil, err
	}
	decryptedusername, err := decryptField(username, c)
	if err != nil {
		return nil, err
	}
	password, err := lastpass.ReadItem(reader)
	if err != nil {
		return nil, err
	}
	decryptedpassword, err := decryptField(password, c)
	if err != nil {
		return nil, err
	}

	return &lastpass.Account{
		ID:       string(id),
		Name:     string(decryptedName),
		Username: string(decryptedusername),
		Password: string(decryptedpassword),
	}, nil
}

func decryptField(field []byte, c cipher.Block) ([]byte, error) {
	length := len(field)

	if length == 0 {
		return nil, nil
	}

	if field[0] == '!' && length%aes.BlockSize == 1 && length > aes.BlockSize*2 {
		// CBC plain decrypt
		return decryptCBCPlain(field[1:], c)
	}
	// ECB plain decrypt
	return nil, fmt.Errorf("not implemented yet")
}

func decryptCBCPlain(field []byte, c cipher.Block) ([]byte, error) {
	// LastPass AES-256/CBC encrypted string starts with an "!".
	if len(field) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	iv, ciphertext := field[:aes.BlockSize], field[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(c, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// TODO: there is some padding here im not sure the best way to remove it yet.
	return ciphertext, nil
}
