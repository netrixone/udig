# Vars and params
GOCMD=go
BINARY_NAME=udig
PACKAGE=github.com/netrixone/udig/cmd/udig
GEODB_NAME=IP2LOCATION-LITE-DB1.IPV6.BIN
INSTALL_DIR=$(shell dirname "`which $(BINARY_NAME)`")

all: build test

clean:
		$(GOCMD) clean -i $(PACKAGE)
		rm -f $(BINARY_NAME)
		rm -f $(GEODB_NAME)

build: deps
		$(GOCMD) build -v -o $(BINARY_NAME) $(PACKAGE)

install: deps test
		$(GOCMD) install $(PACKAGE)
ifneq (,$(wildcard $(GEODB_NAME)))
		cp $(GEODB_NAME) "$(INSTALL_DIR)"
endif

deps:
		$(GOCMD) get -v -t ./...
ifeq (,$(wildcard $(GEODB_NAME)))
		wget -q -O tmp.zip "https://download.ip2location.com/lite/$(GEODB_NAME).ZIP" && unzip -p tmp.zip $(GEODB_NAME) > $(GEODB_NAME) && rm tmp.zip
endif

test: build
		$(GOCMD) test
