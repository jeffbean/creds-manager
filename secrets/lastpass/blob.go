package lastpass

import (
	"io"
)

// A Blob is the non decrypted data parsed into chunks
// each chunk is just the byte payload
type Blob struct {
	Version      uint64
	LocalVersion bool

	AccountChunks []Chunk
}

// parseBlob takes in a reader to parse out the LastPass Blob.
// it only parses the bytes themselves and does not parse them into structs.
func parseBlob(r io.Reader) (*Blob, error) {
	var blob Blob
	chunks, err := parseChunks(r)
	if err != nil {
		return nil, err
	}

	accounts := make([]Chunk, 0)
	for _, chunk := range chunks {
		switch chunk.id {
		case VersionChunk:
			blob.Version = parseVersion(chunk)
		case AccountChunk:
			accounts = append(accounts, chunk)
		}
	}

	blob.AccountChunks = accounts

	return &blob, nil
}

// TODO: implement me
func parseVersion(*chunk) uint64 {
	return 0
}
