MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -euc
.DEFAULT_GOAL := build

# ----------------------------------------
# working environment

venv ?= $(shell echo $${WORKON_HOME:-.venv}/plan-permissions-model)
OS := $(shell uname)

# TODO: this is gross and overly specific right now b/c pynacl doesn't
# have a binary wheel for python3.6 and getting cross-platform dependencies
# set up was just more of a pain than I wanted to deal with for a PoC

$(venv):
	test -d $(venv) || python3.5 -m venv $(venv)


.PHONY: deps
deps: requirements.txt
	$(venv)/bin/pip install -Ur requirements.txt
	touch $(venv)/bin/activate


.PHONY: setup
setup: $(venv) deps

check:
	cd model && $(venv)/bin/pylint *.py

# ----------------------------------------
# demo

run:
	cd model && $(venv)/bin/python ./demo.py
