TVISOR_ARCH ?= $(shell uname -m)
ifeq ($(TVISOR_ARCH), x86_64)
  TVISOR_CARGO_BUILD_TARGET ?= x86_64-unknown-none
  TESTS_CARGO_BUILD_TARGET ?= x86_64-unknown-linux-gnu
else ifeq ($(TVISOR_ARCH), aarch64)
  TVISOR_CARGO_BUILD_TARGET ?= aarch64-unknown-none
  TESTS_CARGO_BUILD_TARGET ?= aarch64-unknown-linux-gnu
else ifeq ($(TVISOR_ARCH), arm64)
  TVISOR_CARGO_BUILD_TARGET ?= aarch64-unknown-none
  TESTS_CARGO_BUILD_TARGET ?= aarch64-unknown-linux-gnu
endif

export TVISOR_CARGO_BUILD_TARGET := $(TVISOR_CARGO_BUILD_TARGET)

TVISOR_MANIFEST := --manifest-path tvisor/Cargo.toml
TESTS_MANIFEST := --manifest-path tvisor-tests/Cargo.toml

.PHONY: check build test all

check:
	@cargo fmt ${TVISOR_MANIFEST} --all -- --check
	@cargo clippy ${TVISOR_MANIFEST} --all --target ${TVISOR_CARGO_BUILD_TARGET} -- -D warnings
	@cargo fmt ${TESTS_MANIFEST} --all -- --check
	@cargo clippy ${TESTS_MANIFEST} --all  --target ${TESTS_CARGO_BUILD_TARGET} -- -D warnings

build:
	@cargo build ${TVISOR_MANIFEST} --target ${TVISOR_CARGO_BUILD_TARGET}
	@cargo build ${TVISOR_MANIFEST} --target ${TVISOR_CARGO_BUILD_TARGET} --release
	@cargo build ${TESTS_MANIFEST} --target ${TESTS_CARGO_BUILD_TARGET}

test: build
	@cargo test ${TVISOR_MANIFEST} --target ${TVISOR_CARGO_BUILD_TARGET}
	@cargo test ${TESTS_MANIFEST}  --target ${TESTS_CARGO_BUILD_TARGET}

all: check build test
