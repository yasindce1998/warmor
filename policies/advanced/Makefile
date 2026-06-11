.PHONY: build clean

build:
	cargo build --target wasm32-unknown-unknown --release
	cp target/wasm32-unknown-unknown/release/warmor_policy_advanced.wasm policy.wasm

clean:
	cargo clean
	rm -f policy.wasm