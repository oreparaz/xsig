CC = cc
CFLAGS = --std=c99 -Os -Wall -Wextra -g

FUZZ_CC = /opt/homebrew/opt/llvm/bin/clang
FUZZ_CFLAGS = --std=c99 -g -O1 -fsanitize=fuzzer,address

SRCS = stack.c der.c eval.c xsig.c p256/p256.c
OBJS = $(SRCS:.c=.o)

.PHONY: all test clean vectors fuzz fuzz-machine001 fuzz-eval fuzz-der

all: test_main

test_vectors.h: gen_test_vectors.go
	cd .. && go run ./c/gen_test_vectors.go

vectors: test_vectors.h

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

test_main: test_vectors.h $(OBJS) test_main.o
	$(CC) $(CFLAGS) -o $@ $(OBJS) test_main.o

test_main.o: test_main.c test_vectors.h
	$(CC) $(CFLAGS) -c -o $@ $<

ceval: $(OBJS) ceval.o
	$(CC) $(CFLAGS) -o $@ $(OBJS) ceval.o

ceval.o: ceval.c
	$(CC) $(CFLAGS) -c -o $@ $<

test: test_main
	./test_main

# Fuzz targets (built with homebrew clang + libFuzzer + ASan)
fuzz_machine001: fuzz_machine001.c $(SRCS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^

fuzz_eval: fuzz_eval.c $(SRCS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^

fuzz_der: fuzz_der.c $(SRCS)
	$(FUZZ_CC) $(FUZZ_CFLAGS) -o $@ $^

fuzz-machine001: fuzz_machine001
	@mkdir -p corpus/machine001
	./fuzz_machine001 corpus/machine001

fuzz-eval: fuzz_eval
	@mkdir -p corpus/eval
	./fuzz_eval corpus/eval

fuzz-der: fuzz_der
	@mkdir -p corpus/der
	./fuzz_der corpus/der

fuzz: fuzz_machine001 fuzz_eval fuzz_der

clean:
	rm -f *.o p256/*.o test_main ceval test_vectors.h fuzz_machine001 fuzz_eval fuzz_der
	rm -rf corpus
