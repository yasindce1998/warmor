.PHONY: build clean

build:
	cargo build --target wasm32-wasi --release
	cp target/wasm32-wasi/release/warmor_policy_example.wasm policy.wasm

clean:
	cargo clean
	rm -f policy.wasm