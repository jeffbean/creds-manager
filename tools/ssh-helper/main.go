package main

import (
	"fmt"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ed25519"

	"github.com/jeffbean/creds-manager/ssh"
	"github.com/jessevdk/go-flags"
	"golang.org/x/crypto/ssh/agent"
)

// Flags are the commands command line flags
type Flags struct {
	Name string `long:"name" required:"true" description:"The name of the ssh-key to manage." positional-arg:"true"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {
	f := &Flags{}
	parser := flags.NewParser(f, flags.PassDoubleDash)

	if _, err := parser.Parse(); err != nil {
		return err
	}
	// ED doesn't use bitsize
	keyPair, err := ssh.GenerateSSHKeyPair("", ssh.ED25519, 0)
	if err != nil {
		return fmt.Errorf("failed to create ssh keys: %v", err)
	}
	if err := AddKeyToAgent(keyPair); err != nil {
		return fmt.Errorf("failed to add key to ssh agent: %v", err)
	}

	return nil
}

func AddKeyToAgent(kp *ssh.KeyPair) error {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return err
	}
	sshClient := agent.NewClient(sshAgent)
	addKey := agent.AddedKey{
		LifetimeSecs: 120,
	}
	switch privateKey := kp.PrivateKey.(type) {
	case ed25519.PrivateKey:
		addKey.PrivateKey = &privateKey
	}
	return sshClient.Add(addKey)
}
