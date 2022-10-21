CC=gcc
CFALGS=--wall

DEPS:=pt-parse-internal.h pt-parse-oppcode.h asm-parse-internal.h asm-parse.h
OBJ:=asm-parse.o pt-parse.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

main: parser

parser: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm -f ./parser $(OBJ)