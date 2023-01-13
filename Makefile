CC=g++
CFLAGS=-Wall -std=c++20 -lpthread -O3

DEPS:=pt-parse-internal.h pt-parse-oppcode.h \
	  asm-parse-internal.h asm-parse.h asm-types.h \
	  pt-parse.h pt-parse-types.h types.h \
	  mapping-parse.h
OBJ:=parser.o asm-parse.o pt-parse.o mapping-parse.o

%.o: %.cpp $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: parser

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm -f ./parser $(OBJ)