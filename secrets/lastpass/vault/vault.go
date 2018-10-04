package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"log"

	"github.com/jeffbean/creds-manager/api"
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

// Load take a secret name and returns the secret with that name, if found
func (v *Vault) Load(ctx context.Context, name string) *api.Secret {
	for _, a := range v.Accounts {
		if a.Name == name {
			return &api.Secret{Name: name, Value: a}
		}
	}
	return nil
}

// Save is not implemented for lastpass
func (v *Vault) Save(ctx context.Context, s *api.Secret) error {
	return errors.New("Save not implemented for lastpass")
}

func parseAccounts(accountChunks []lastpass.Chunk, c cipher.Block) ([]*lastpass.Account, error) {
	accounts := make([]*lastpass.Account, 0)
	for _, accountChunk := range accountChunks {
		acct, err := parseAccount(accountChunk, c)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, acct)
	}
	return accounts, nil
}

func parseAccount(chunk lastpass.Chunk, c cipher.Block) (*lastpass.Account, error) {
	// TODO: reading fields is a little it weird but i like the fact the chunk can just be read holistically
	fields, err := chunk.ReadFields()
	if err != nil {
		return nil, err
	}
	if len(fields) < 8 {
		for _, f := range fields {
			log.Printf("%v\n", f)
		}
		return nil, fmt.Errorf("failed to parse account fields expected at least 8 fields, found: %v", len(fields))
	}

	decryptedName, err := decryptField(fields[1], c)
	if err != nil {
		return nil, err
	}
	decryptedpassword, err := decryptField(fields[7], c)
	if err != nil {
		return nil, err
	}

	return &lastpass.Account{
		ID:   string(fields[0]),
		Name: string(decryptedName),
		// Username: string(decryptedusername),
		Password: string(decryptedpassword),
	}, nil
}

func decryptField(field lastpass.Field, c cipher.Block) ([]byte, error) {
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
