.PHONY: test_debug debug

test_debug: 
	env RUST_LOG=debug cargo test -- --nocapture

debug:
	env RUST_LOG=debug cargo run
