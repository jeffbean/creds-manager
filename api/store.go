package api

import (
	"context"
)

type Secret struct {
	Name  string
	Value interface{}
}

type Vault interface {
	// Parse(key string) (*Secret, error)
	Load(context.Context, string) (*Secret, error)
	Save(context.Context, *Secret) error
}
