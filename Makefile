# This repo's root import path (under GOPATH).
PKG := github.com/idefixcert/dhcp-client

ALL_PLATFORMS := darwin/amd64 linux/amd64

# Used internally.  Users should pass GOOS and/or GOARCH.
OS := $(if $(GOOS),$(GOOS),$(shell go env GOOS))
ARCH := $(if $(GOARCH),$(GOARCH),$(shell go env GOARCH))

# If you want to build all binaries, see the 'all-build' rule.
all: build

# For the following OS/ARCH expansions, we transform OS/ARCH into OS_ARCH
# because make pattern rules don't match with embedded '/' characters.
build-%:
	@$(MAKE) build                        \
	    --no-print-directory              \
	    GOOS=$(firstword $(subst _, ,$*)) \
	    GOARCH=$(lastword $(subst _, ,$*))

build: buildbin/$(OS)_$(ARCH)

# Directories that we need created to build/test.
BUILD_DIR := bin/$(OS)_$(ARCH)

buildbin/%: $(BUILD_DIR)
	@echo build $(OS)_$(ARCH) $(VERSION)
	env GOOS=$(OS) GOARCH=$(ARCH) go build -o $(BUILD_DIR)/dhcpclient ${PKG}/cmd/dhcp-client/

$(BUILD_DIR):
	@echo build dir
	@mkdir -p $@

clean: bin-clean

bin-clean:
	rm -rf bin
