PROJECT_NAME := leach
SRC := $(filter-out %_test.go,$(wildcard *.go))
WEB_SRC := $(wildcard web/**)
BUILD_DIR := bin
RELEASE_DIR := $(BUILD_DIR)/release
CI_COMMIT_REF_SLUG ?= $(shell cat VERSION)
CI_COMMIT_SHA ?= $(shell git rev-parse HEAD | head -c 8)
LD_VERSION_FLAGS = -X main.Version=$(CI_COMMIT_REF_SLUG) -X main.GitSHA=$(CI_COMMIT_SHA)
SED := $(if $(shell which gsed),gsed,sed)

all: $(BUILD_DIR)/$(PROJECT_NAME)
release: $(RELEASE_DIR)/$(PROJECT_NAME)
packr: main-packr.go

main-packr.go: $(WEB_SRC)
	set -e;\
	MODULE_NAME=$$(head -1 go.mod | cut -f 2 -d " ");\
	packr2;\
	$(SED) -i "s,$${PWD#/},$$MODULE_NAME," $@;\

$(BUILD_DIR)/$(PROJECT_NAME): $(SRC) go.mod go.sum
	go build -o $@ -ldflags="$(LD_VERSION_FLAGS)"

$(RELEASE_DIR)/$(PROJECT_NAME): $(SRC) packr go.mod go.sum
	CGO_ENABLED=0 go build \
	-ldflags="-w -s $(LD_VERSION_FLAGS)" \
	-o $@

docker:
	docker build -t $(PROJECT_NAME) .

clean:
	packr2 clean
	rm -rf $(BUILD_DIR)

test:
	go test -cover -v

.PHONY: all clean release docker test packr
