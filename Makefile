default: build test

BINS = tools/ssh-helper/ssh-helper \
	tools/lptool/lptool

PROJECT_ROOT = github.com/jeffbean/creds-manager

GO_BIN_BUILD=go build -o $@ $(bin_main_pkg)

bin_main_dir=$(abspath $(GOPATH)/$(PROJECT_ROOT)/$(dir $@))
bin_main_pkg=$(subst $(GOPATH)/,,$(bin_main_dir))

build: $(BINS)

test:
	go test -v -race ./...

$(BINS):
	$(GO_BIN_BUILD)

tools/ssh-helper/ssh-helper: $(wildcard tools/ssh-helper/*.go \
	ssh/*.go)

tools/lptool/lptool: $(wildcard **/*.go)

clean:
	rm $(BINS)