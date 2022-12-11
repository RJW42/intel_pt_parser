CC=g++
CFLAGS=-Wall -std=c++20 -O3

DEPS:=pt-parse-internal.h pt-parse-oppcode.h \
	  asm-parse-internal.h asm-parse.h
OBJ:=parser.o asm-parse.o pt-parse.o

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: parser

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm -f ./parser $(OBJ)