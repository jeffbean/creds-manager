package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"
	"time"

	"github.com/jeffbean/creds-manager/ssh"
	"github.com/jessevdk/go-flags"
)

// Flags are the commands command line flags
type Flags struct {
	OutputFile   flags.Filename `short:"f" description:"Output file"`
	AgentTimeout time.Duration  `short:"t" long:"agentTime" description:"The amount of time to live in the ssh agent" default:"20h"`
	Comment      string         `short:"C" long:"comment" description:"An ssh key comment."`

	Args struct {
		Name string
	} `description:"The name of the ssh-key to manage." positional-args:"yes" required:"yes" `
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

	// if not specified we just make a temp dir and put it there for you to do what you will with it
	if f.OutputFile == "" {
		tmpDir, err := ioutil.TempDir("", "ssh-helper")
		if err != nil {
			return err
		}

		f.OutputFile = flags.Filename(filepath.Join(tmpDir, f.Args.Name))
	}

	log.Printf("f: %#v", f)
	// ED25519 doesn't use bitsize
	keyPair, err := ssh.GenerateSSHKeyPair(ssh.ED25519, 0)
	if err != nil {
		return fmt.Errorf("failed to create ssh keys: %v", err)
	}

	if err := ssh.WriteKeysToDisk(string(f.OutputFile), keyPair, f.Comment); err != nil {
		return fmt.Errorf("failed to write ssh files: %v", err)
	}

	comment := fmt.Sprintf("[ssh-helper %s]", f.Comment)
	if err := ssh.AddKeyToAgent(keyPair, ssh.WithTimeout(f.AgentTimeout), ssh.WithComment(comment)); err != nil {
		return fmt.Errorf("failed to add key to ssh agent: %v", err)
	}

	return nil
}
