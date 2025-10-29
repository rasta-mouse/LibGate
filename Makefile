CC_64=x86_64-w64-mingw32-gcc

all: libgate.x64.zip

bin:
	mkdir bin

libgate.x64.zip: bin
	$(CC_64) -DWIN_X64 -shared -Wall -Wno-pointer-arith -c src/gate.c -o bin/gate.x64.o
	zip -q -j libgate.x64.zip bin/*.x64.o

clean:
	rm -rf bin/*.o
	rm -f libgate.x64.zip