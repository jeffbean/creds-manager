package ssh

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh/agent"
)

const _sshUnixVarName = "SSH_AUTH_SOCK"

type agentKeyOption func(*agent.AddedKey)

func WithTimeout(t time.Duration) agentKeyOption {
	return func(ak *agent.AddedKey) {
		ak.LifetimeSecs = uint32(t.Seconds())
	}
}

func WithComment(comment string) agentKeyOption {
	return func(ak *agent.AddedKey) {
		ak.Comment = comment
	}
}

func AddKeyToAgent(kp *KeyPair, addKeyOpts ...agentKeyOption) error {
	sshAgent, err := net.Dial("unix", os.Getenv(_sshUnixVarName))
	if err != nil {
		return err
	}
	sshClient := agent.NewClient(sshAgent)
	addKey := agent.AddedKey{}

	switch privateKey := kp.PrivateKey.(type) {
	case *ed25519.PrivateKey:
		addKey.PrivateKey = privateKey
	default:
		return fmt.Errorf("unknown key type for agent ")
	}

	for _, opt := range addKeyOpts {
		opt(&addKey)
	}

	return sshClient.Add(addKey)
}
