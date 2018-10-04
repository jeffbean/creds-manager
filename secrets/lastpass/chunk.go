package lastpass

import (
	"bytes"
	"encoding/binary"
	"io"
)

type ChunkID [4]byte

var (
	// AccountChunk is the byte header for an account
	AccountChunk ChunkID = [4]byte{'A', 'C', 'C', 'T'}
	// VersionChunk id for a chunk
	VersionChunk ChunkID = [4]byte{'L', 'P', 'A', 'V'}
)

type Chunk interface {
	GetID() ChunkID
	ReadFields() ([]Field, error)
}

type Field []byte

type chunk struct {
	id   ChunkID
	data []byte
}

// ReadFields reads all the fields out of a chunk
// the returned slice of fields will vary from the type of Chunk it is
// and is up to the caller on how the layout of the fields is parsed
func (c *chunk) ReadFields() ([]Field, error) {
	r := bytes.NewReader(c.data)
	fields := make([]Field, 0)
	for {
		field, err := readField(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		fields = append(fields, field)
	}

	return fields, nil
}

func (c *chunk) GetID() ChunkID {
	return c.id
}

func readField(r io.Reader) (Field, error) {
	data, err := readItem(r)
	if err != nil {
		return nil, err
	}
	return Field(data), nil
}

func readItem(r io.Reader) ([]byte, error) {
	size, err := readUint32(r)
	if err != nil {
		return nil, err
	}

	b := make([]byte, size)
	n, err := r.Read(b)
	if err != nil {
		return nil, err
	}

	return b[:n], nil
}

func parseChunks(r io.Reader) ([]*chunk, error) {
	chunks := []*chunk{}
	for {
		chunk, err := readChunk(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		chunks = append(chunks, chunk)
	}
	return chunks, nil
}

//   0000: "XXXX"
//   0004: 4
//   0008: 0xDE 0xAD 0xBE 0xEF
//   000C: --- Next chunk ---
func readChunk(r io.Reader) (*chunk, error) {
	chunkID, err := readChunkID(r)
	if err != nil {
		return nil, err
	}

	data, err := readItem(r)
	if err != nil {
		return nil, err
	}

	return &chunk{id: chunkID, data: data}, nil
}

func readChunkID(r io.Reader) (ChunkID, error) {
	var b ChunkID
	if _, err := r.Read(b[:]); err != nil {
		return b, err
	}

	return b, nil
}

func readUint32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := r.Read(b[:]); err != nil {
		return 0, err
	}

	return binary.BigEndian.Uint32(b[:]), nil
}
