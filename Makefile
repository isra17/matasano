all: set1 set2

set1: set1.rs
	rustc -L . set1.rs

set2: set2.rs
	rustc -g -L . set2.rs

run:
	./set2
