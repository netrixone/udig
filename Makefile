# Vars and params
GOCMD=go
BINARY_NAME=udig

all: build test

clean:
		$(GOCMD) clean -i $(BINARY_NAME)
		rm -f $(BINARY_NAME)

build: deps
		$(GOCMD) install
		$(GOCMD) build -v -o $(BINARY_NAME) github.com/netrixone/udig/cmd/udig

deps:
		$(GOCMD) get -v -t ./...

test: build
		$(GOCMD) test
