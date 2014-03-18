.PHONY: all


all:
	rustc -g src/lib.rs
	rustc -g --test src/lib.rs
	rustc -g -L. --test src/test.rs
	rustc -g -L. src/main.rs
