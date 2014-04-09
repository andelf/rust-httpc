.PHONY: all


all:
	rustc -g src/httpc/lib.rs
	rustc -g --test src/httpc/lib.rs
	rustc -g -L. --test examples/test.rs
	rustc -g -L. examples/main.rs
	rustc -g -L. examples/youdao_fanyi.rs
