CC=gcc
CFALGS=--wall

DEPS=parse-internal.h parse-oppcode.h
OBJ=parse.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: parser

parser: $(OBJ)
	$(CC) -o $@ $< $(CFLAGS)

clean: 
	rm ./parser $(OBJ)