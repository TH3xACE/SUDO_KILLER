CFLAGS  = -W -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual \
		            -Wcast-align -Wwrite-strings -Wmissing-prototypes -Winline -Wundef

#CFLAGS += -DDEBUG

all: dmiwrite

dmiwrite:
	gcc $(CFLAGS) dmiwrite.c util.c -o dmiwrite

clean:
	rm -f dmiwrite
