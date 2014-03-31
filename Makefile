.PHONY: all


all:
	rustc -g src/lib.rs
	rustc -g --test src/lib.rs
	rustc -g -L. --test examples/test.rs
	rustc -g -L. examples/main.rs
	rustc -g -L. examples/youdao_fanyi.rs
