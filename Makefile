default: build test

BINS = tools/ssh-helper/ssh-helper creds-manager

GO_BIN_BUILD=go build -o $@

build: $(BINS)

test:
	go test -v -race ./...

$(BINS):
	$(GO_BIN_BUILD)

tools/ssh-helper/ssh-helper: $(wildcard tools/ssh-helper/*.go \
	ssh/*.go)

creds-manager: $(wildcard **/*.go)
