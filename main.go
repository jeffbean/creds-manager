package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/jeffbean/creds-manager/secrets/lastpass/vault"

	"github.com/jeffbean/creds-manager/secrets/lastpass"
	"github.com/jeffbean/creds-manager/ssh"
)

func main() {
	if err := runLP(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keyPair, err := ssh.GenerateSSHKeyPair("foobar", ssh.RSAPrivateKey, 1024)
	if err != nil {
		return fmt.Errorf("failed to gen keypair: %v", err)
	}

	tmpDir, err := ioutil.TempDir("", "ssh-test")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	fmt.Println(tmpDir)

	return ssh.WriteKeysToDirectory(keyPair, tmpDir)
}

func runLP() error {
	b, err := ioutil.ReadFile("credentials.txt")
	if err != nil {
		return err
	}

	lines := strings.Split(string(b), "\n")
	username := lines[0]
	password := lines[1]

	client, err := lastpass.NewClient()
	if err != nil {
		return err
	}
	defer func() {
		log.Println("logging out")

		if err := client.Logout(); err != nil {
			log.Fatal(err)
		}
	}()

	log.Println("logging in to lastpass")
	if err := client.Login(username, password); err != nil {
		return err
	}

	log.Println("getting accounts")
	blob, err := client.GetBlob(context.TODO())
	if err != nil {
		return err
	}

	vault, err := vault.NewVault(blob, client.MakeEncryptionKey(username, password))
	if err != nil {
		return err
	}
	for _, account := range vault.Accounts {
		fmt.Printf("account: %#v\n", account)
	}
	return nil
}
