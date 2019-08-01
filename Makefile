all:
	cargo build
	cbindgen --config cbindgen.toml --crate pixel --output c_wrapper/pixel_c.h
	gcc c_wrapper/*.c -L./target/debug -lpixel -lpthread -ldl -o c_wrapper/c_example
	c_wrapper/c_example

lib:
#	cargo build --release
	gcc -c c_wrapper/*.c -L./target/debug -lpixel -lpthread -ldl -o bls-c-bind.o
#	gcc -c go_wrapper/*.c -L./target/release -lbls_signature -lpthread -ldl -o bls-go-bind.o
#	ar rcs libbls.a bls-c-bind.o bls-go-bind.o
	rm *.o

clean:
	cargo clean
	rm test
