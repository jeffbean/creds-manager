package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"log"

	"github.com/jeffbean/creds-manager/secrets/lastpass/ecb"

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
// it could be local - we want to keep the decryption seprate to allow
// the callers to just feed in a Blob that could be from memory or a file and not
// assume it comes from lastpass.com
func NewVault(blob *lastpass.Blob, encryptionKey []byte) (*Vault, error) {
	cipher, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	// classify chunks, parse them, and decrypt them here.
	accountChunks := make([]lastpass.Chunk, 0)
	for _, chunk := range blob.Chunks {
		switch chunk.GetID() {
		case lastpass.AccountChunk:
			accountChunks = append(accountChunks, chunk)
		}
	}

	accounts, err := parseAccounts(accountChunks, cipher)
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

// AccountFieldIndex is the index marker for a given account field
type AccountFieldIndex int

// Enum for the field index of the named field
const (
	ID AccountFieldIndex = iota
	Name
	Group
	URL
	Note

	Username = iota + 2
	Password
)

func parseAccount(chunk lastpass.Chunk, c cipher.Block) (*lastpass.Account, error) {
	fields, err := chunk.ReadFields()
	if err != nil {
		return nil, err
	}
	if len(fields) < Password {
		for _, f := range fields {
			log.Printf("%v\n", f)
		}
		return nil, fmt.Errorf("failed to parse account fields expected at least %d fields, found: %v", Password, len(fields))
	}

	var acct lastpass.Account
	acct.ID = string(fields[ID])
	// reflect might help here - i went down a path of writing an Unmarshal for this thing but
	// i think lastpass data structure is not that of the future. protobuf will do fine
	// and we just need this to read out the lastpass data.
	if acct.Name, err = getStringField(fields[Name], c); err != nil {
		return nil, err
	}
	if acct.Group, err = getStringField(fields[Group], c); err != nil {
		return nil, err
	}
	if acct.Notes, err = getStringField(fields[Note], c); err != nil {
		return nil, err
	}
	url, err := decodeHex(fields[URL])
	if err != nil {
		return nil, err
	}
	acct.URL = string(url)
	if acct.Username, err = getStringField(fields[Username], c); err != nil {
		return nil, err
	}
	if acct.Password, err = getStringField(fields[Password], c); err != nil {
		return nil, err
	}

	return &acct, nil
}

func getStringField(field lastpass.Field, c cipher.Block) (string, error) {
	data, err := decryptField(field, c)
	if err != nil {
		return "", err
	}
	return string(data), nil
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
	// This was not put into Go by default since it was seen as easy and not secure.
	return decryptECBPlain(field, c)
}

func decryptECBPlain(field []byte, c cipher.Block) ([]byte, error) {
	// LastPass AES-256/CBC encrypted string starts with an "!".
	if len(field) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	_, ciphertext := field[:aes.BlockSize], field[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := ecb.NewECBDecrypter(c)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return unpad(ciphertext, c.BlockSize())
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

	return unpad(ciphertext, c.BlockSize())
}

// padding is a common pkcs technique and we need to remove the padding.
func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes of the padding should
	// be the length of the padding
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("found invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}

func decodeHex(b []byte) ([]byte, error) {
	d := make([]byte, len(b))
	n, err := hex.Decode(d, b)
	if err != nil {
		return nil, err
	}
	return d[:n], nil
}
