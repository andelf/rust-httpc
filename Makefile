.PHONY: all


all:
	rustc -g2 src/lib.rs
	rustc -g2 --test src/lib.rs
	rustc -g2 -L. --test src/test.rs
	rustc -g2 -L. src/main.rs
