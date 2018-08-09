MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -euc
.DEFAULT_GOAL := build
GOPATH := $(abspath $(shell pwd)/../../../..)

help:
	@echo -e "\033[32m"
	@echo "This demo uses glide to manage its dependencies. Download the latest"
	@echo "version from https://github.com/Masterminds/glide/releases"
	@echo "Targets in this Makefile will set the GOPATH appropriately if the"
	@echo "repository is within ./src/github.com/plan-tools/permissions-model"
	@echo "Otherwise... good luck."
	@echo "GOPATH=$(GOPATH)"

# ----------------------------------------
# working environment

GLIDE_ERR := "You need glide installed to set up this project. Download the latest version from https://github.com/Masterminds/glide/releases"
check-glide:
	@command -v glide || { echo $(GLIDE_ERR) ; exit 1;}

setup: check-glide
	mkdir -p vendor
	GOPATH=$(GOPATH) glide up

build:
	GOPATH=$(GOPATH) go build -o demo main.go

# ----------------------------------------
# demo

run:
	GOPATH=$(GOPATH) go run main.go

# set a single package to test by passing the PKG variable
PKG ?=
ifeq ($(PKG), )
PKG := ./...
else
PKG := github.com/plan-tools/permissions-model/$(PKG)
endif

test:
	GOPATH=$(GOPATH) go test -v $(PKG)
