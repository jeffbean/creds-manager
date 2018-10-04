package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/jeffbean/creds-manager/secrets/lastpass"
	"github.com/jeffbean/creds-manager/secrets/lastpass/vault"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
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
