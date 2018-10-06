package main

import (
	"log"

	"github.com/jessevdk/go-flags"
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
	var f Flags
	parser := flags.NewParser(f, flags.PassDoubleDash)

	if _, err := parser.Parse(); err != nil {
		return err
	}

	return nil
}
