cryptor: src/main.c
	gcc -Wall -Wextra -g -D_POSIX_C_SOURCE=200809L -o crypto src/main.c -lssl -lcrypto

test: test/tests.c src/crypt.c
	gcc -Wall -Wextra -g -D_POSIX_C_SOURCE=200809L -DTESTING -o test_runner test/tests.c src/crypt.c -lssl -lcrypto -lcunit
	./test_runner

clean:
	rm -f crypto test_runner

.PHONY: cryptor test clean
