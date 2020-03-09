# Vars and params
GOCMD=go
BINARY_NAME=udig
PACKAGE=github.com/netrixone/udig/cmd/udig

all: build test

clean:
		$(GOCMD) clean -i ${PACKAGE}
		rm -f $(BINARY_NAME)

build: deps
		$(GOCMD) install
		$(GOCMD) build -v -o $(BINARY_NAME) ${PACKAGE}

deps:
		$(GOCMD) get -v -t ./...

test: build
		$(GOCMD) test
