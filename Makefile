.PHONY : all build builddir install ppkmip kmipgen lint vet clean fmt generate test cover up down docker bash fish tidy update tools pykmip-server gen-certs

SHELL = bash
BUILD_FLAGS =
TEST_FLAGS =
COMPOSE ?= docker-compose
APP_NAME := kms

help:
	@echo ""
	@echo "-----------------------------------------------------------------------------------"
	@echo "make all          - remove all"
	@echo "make build        - build a local executable"
	@echo "make install      - install the executable"
	@echo "make clean        - remove build files"
	@echo "make tidy         - go mod tidy"
	@echo "make update       - go get -u ./..."
	@echo "make lint         - golangci-lint run"
	@echo "make vet          - go vet ./..."
	@echo "make fmt          - gofumpt -w -l ."
	@echo "make kms          - build $(APP_NAME) executable"
	@echo ""

all: fmt build up test lint

build:
	go build $(BUILD_FLAGS) ./...

builddir:
	mkdir -p -m 0777 build

install:
	go install ./cmd/ppkmip
	go install ./cmd/kmipgen
	install ./$(APP_NAME) /usr/local/bin

ppkmip: builddir
	GOOS=darwin GOARCH=amd64 go build -o build/ppkmip-macos ./cmd/ppkmip
	GOOS=windows GOARCH=amd64 go build -o build/ppkmip-windows.exe ./cmd/ppkmip
	GOOS=linux GOARCH=amd64 go build -o build/ppkmip-linux ./cmd/ppkmip

kmipgen:
	go install ./cmd/kmipgen

lint:
	golangci-lint run

vet:
	go vet ./...

clean:
	rm -rf build/*
	rm -rf $(APP_NAME)

fmt:
	gofumpt -w -l .

# generates go code structures representing all the enums, mask, and tags defined
# in the KMIP spec.  The source specifications are stored in kmip14/kmip_1_4.json
# and ttls/kmip20/kmip_2_0_additions.json.  The generated .go files are named *_generated.go
#
# the kmipgen tool (defined in cmd/kmipgen) is used to generate the source.  This tool can
# be used independently to generate source for future specs or vendor extensions.
#
# this target only needs to be run if the json files are changed.  The generated
# go files should be committed to source control.
generate:
	go generate ./...

test:
	go test $(BUILD_FLAGS) $(TEST_FLAGS) ./...

# creates a test coverage report, and produces json test output.  useful for ci.
cover: builddir
	go test $(TEST_FLAGS) -v -covermode=count -coverprofile=build/coverage.out -json ./...
	go tool cover -html=build/coverage.out -o build/coverage.html

# brings up the projects dependencies in a compose stack
up:
	$(COMPOSE) build --pull pykmip-server
	$(COMPOSE) run --rm dependencies

# brings down the projects dependencies
down:
	$(COMPOSE) down -v --remove-orphans

# runs the build inside a docker container.  useful for ci to completely encapsulate the
# build environment.
docker:
	$(COMPOSE) build --pull builder
	$(COMPOSE) run --rm builder make all cover

# opens a shell into the build environment container.  Useful for troubleshooting the
# containerized build.
bash:
	$(COMPOSE) build --pull builder
	$(COMPOSE) run --rm builder bash

# opens a shell into the build environment container.  Useful for troubleshooting the
# containerized build.
fish:
	$(COMPOSE) build --pull builder
	$(COMPOSE) run --rm builder fish

tidy:
	go mod tidy

# use go mod to update all dependencies
update:
	go get -u ./...
	go mod tidy

# install tools used by the build.  typically only needs to be run once
# to initialize a workspace.
tools: kmipgen
	go install mvdan.cc/gofumpt@latest
	go install golang.org/x/tools/cmd/cover@latest
	sh -c "$$(wget -O - -q https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh || echo exit 2)" -- -b $(shell go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)

pykmip-server: up
	$(COMPOSE) exec pykmip-server tail -f server.log

gen-certs:
	openssl req -x509 -newkey rsa:4096 -keyout pykmip-server/server.key -out pykmip-server/server.cert -days 3650 -nodes -subj '/CN=localhost'

kms:
	@echo "Build local $(APP_NAME)..."
	go build -o $(APP_NAME) -ldflags "-X main.buildTime=`date -u '+%Y-%m-%dT%H:%M:%S'`" ./cmd/$(APP_NAME)/main.go
	ls -lh $(APP_NAME)
