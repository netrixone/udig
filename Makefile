# Vars and params
GOCMD=go
BINARY_NAME=udig

all: build

clean:
		$(GOCMD) clean -i $(BINARY_NAME)

build: deps
		$(GOCMD) install
		$(GOCMD) build -v -o $(BINARY_NAME) udig/cmd/udig

deps:
		$(GOCMD) get -v -t ./...

test: build
		$(GOCMD) test
