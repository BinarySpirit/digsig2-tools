CFLAGS = -g3 -O2 -Wall $(shell pkg-config --cflags gnutls)
LDLIBS = $(shell pkg-config --libs gnutls)

all: sign verify

sign: sign.o common.o
verify: verify.o common.o

clean:
	-rm -f *.o sign verify
