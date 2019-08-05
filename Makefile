all:
	# this build a debug library; we will need to change to
	#		`cargo build --release`
	# for deployment
	cargo build
	# we use cbindgen crate to automatically generate the header for C
	cbindgen --config cbindgen.toml --crate pixel --output c_wrapper/pixel_c.h
	# this is an example of how the APIs can be called in c
	# for released version of the library, change into
	# 	`gcc c_wrapper/*.c -L./target/release -lpixel -lpthread -ldl -o c_wrapper/c_example`

test_vector_c:
	cargo build
	cbindgen --config cbindgen.toml --crate pixel --output c_wrapper/pixel_c.h
	gcc c_wrapper/*.c -L./target/debug -lpixel -lpthread -ldl -o c_wrapper/c_example
	c_wrapper/c_example
	python test_buf/test_vector.py

test_vector_rust:
	cd test_vector; cargo run

test_vector_python:
	cd pixel-python; python test_vector.py

test: test_vector_rust test_vector_python test_vector_c

# lib:
# #	cargo build --release
# 	gcc -c c_wrapper/*.c -L./target/debug -lpixel -lpthread -ldl -o bls-c-bind.o
# #	gcc -c go_wrapper/*.c -L./target/release -lbls_signature -lpthread -ldl -o bls-go-bind.o
# #	ar rcs libbls.a bls-c-bind.o bls-go-bind.o
# 	rm *.o

clean:
	cargo clean
	rm c_wrapper/c_example
	rm test_buf/*.txt
