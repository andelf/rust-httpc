
.PHONY: all


all:
	rustc -g src/http/lib.rs
	rustc -g --test src/http/lib.rs
	rustc -g -L. --test src/http/test.rs
	rustc -g -L. src/http/main.rs
