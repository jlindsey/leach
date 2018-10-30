PROJECT_NAME := porter
SRC := $(filter-out %_test.go,$(wildcard *.go))
BUILD_DIR := bin
RELEASE_DIR := $(BUILD_DIR)/release

all: $(BUILD_DIR)/$(PROJECT_NAME)

$(BUILD_DIR)/$(PROJECT_NAME): $(SRC) go.mod go.sum
	go build -o $@

$(RELEASE_DIR)/$(PROJECT_NAME): $(SRC) go.mod go.sum
	go build \
	-ldflags="-w -s -X main.Version=$(CI_COMMIT_REF_SLUG) -X main.GitSHA=$(CI_COMMIT_SHA)" \
	-o $@

release: $(RELEASE_DIR)/$(PROJECT_NAME)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean release