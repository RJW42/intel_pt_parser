CC=g++
CFLAGS=-Wall -std=c++20

DEPS:=pt-parse-internal.h pt-parse-oppcode.h \
	  asm-parse-internal.h asm-parse.h \
	  qemu-source-parse-internal.h qemu-source-parse.h
OBJ:=asm-parse.o pt-parse.o qemu-source-parse.o

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: parser

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm -f ./parser $(OBJ)