.PHONY: all build build-rust build-go test test-rust test-go clean dev help

# Project paths
RUST_FFI_DIR = pkg/ffi/rust
RUST_TARGET_DIR = $(RUST_FFI_DIR)/target/release
RUST_LIB = libzcash_t2o_ffi
BIN_DIR = bin

# Platform detection
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    LIB_EXT = dylib
    LIB_PATH_VAR = DYLD_LIBRARY_PATH
else
    LIB_EXT = so
    LIB_PATH_VAR = LD_LIBRARY_PATH
endif

all: build

# Build Rust FFI library
build-rust:
	@echo "Building Rust FFI library..."
	cd $(RUST_FFI_DIR) && cargo build --release
	@echo "Built: $(RUST_TARGET_DIR)/$(RUST_LIB).$(LIB_EXT)"
	@ls -lh $(RUST_TARGET_DIR)/$(RUST_LIB).a $(RUST_TARGET_DIR)/$(RUST_LIB).$(LIB_EXT)

# Build Go binary
build-go: build-rust
	@echo "Building Go binary..."
	@mkdir -p $(BIN_DIR)
	CGO_LDFLAGS="-L$(PWD)/$(RUST_TARGET_DIR)" \
	go build -o $(BIN_DIR)/zcash-t2o ./cmd/zcash-t2o
	@echo "Built: $(BIN_DIR)/zcash-t2o"

build: build-go

# Test Rust FFI
test-rust: build-rust
	@echo "Testing Rust FFI..."
	cd $(RUST_FFI_DIR) && cargo test

# Test Go packages
test-go: build-rust
	@echo "Testing Go packages..."
	CGO_LDFLAGS="-L$(PWD)/$(RUST_TARGET_DIR)" \
	$(LIB_PATH_VAR)="$(PWD)/$(RUST_TARGET_DIR):$$$(LIB_PATH_VAR)" \
	go test -v ./...

test: test-rust test-go

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	cd $(RUST_FFI_DIR) && cargo clean
	rm -rf $(BIN_DIR)
	go clean -cache

# Development mode - just build Rust and show env vars
dev: build-rust
	@echo "Development mode - Rust library built"
	@echo ""
	@echo "Set environment for manual Go development:"
	@echo "  export CGO_LDFLAGS=\"-L$(PWD)/$(RUST_TARGET_DIR)\""
	@echo "  export $(LIB_PATH_VAR)=\"$(PWD)/$(RUST_TARGET_DIR):$$$(LIB_PATH_VAR)\""

# Show help
help:
	@echo "zcash-t2o build system"
	@echo ""
	@echo "Targets:"
	@echo "  make build       - Build Rust FFI and Go binary (default)"
	@echo "  make build-rust  - Build only Rust FFI library"
	@echo "  make build-go    - Build only Go binary (builds Rust first)"
	@echo "  make test        - Run all tests (Rust + Go)"
	@echo "  make test-rust   - Run Rust tests"
	@echo "  make test-go     - Run Go tests"
	@echo "  make clean       - Remove build artifacts"
	@echo "  make dev         - Build Rust and show env vars for development"
	@echo "  make help        - Show this help"
	@echo ""
	@echo "Output:"
	@echo "  Binary: $(BIN_DIR)/zcash-t2o"
	@echo "  Rust library: $(RUST_TARGET_DIR)/$(RUST_LIB).$(LIB_EXT)"
