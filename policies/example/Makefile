.PHONY: build clean

build:
	cargo build --target wasm32-wasip1 --release
	cp target/wasm32-wasip1/release/warmor_policy_example.wasm policy.wasm

clean:
	cargo clean
	rm -f policy.wasm