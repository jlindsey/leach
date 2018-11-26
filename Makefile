PROJECT_NAME := leach
SRC := $(filter-out %_test.go,$(wildcard *.go))
WEB_SRC := $(wildcard web/**)
BUILD_DIR := bin
RELEASE_DIR := $(BUILD_DIR)/release

all: $(BUILD_DIR)/$(PROJECT_NAME)
release: $(RELEASE_DIR)/$(PROJECT_NAME)
packr: main-packr.go

main-packr.go: $(WEB_SRC)
	packr2

$(BUILD_DIR)/$(PROJECT_NAME): $(SRC) go.mod go.sum
	go build -o $@ -ldflags="-X main.Version=dev -X main.GitSHA=$(shell git rev-parse HEAD | head -c 8)"

$(RELEASE_DIR)/$(PROJECT_NAME): $(SRC) packr go.mod go.sum
	go build \
	-ldflags="-w -s -X main.Version=$(CI_COMMIT_REF_SLUG) -X main.GitSHA=$(CI_COMMIT_SHA)" \
	-o $@

docker: release
	docker build -t $(PROJECT_NAME) .

clean:
	packr2 clean
	rm -rf $(BUILD_DIR)

test:
	go test -cover -v

.PHONY: all clean release docker test packr
