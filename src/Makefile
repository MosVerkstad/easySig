CC=g++
CFLAGS=-lpcap -lrt -pthread
CPPFILES=*.cpp
HFILES=-I.
OFILE=easySig

build:
	$(CC) -o $(OFILE) $(CPPFILES) $(HFILES) $(CFLAGS)
clean:
	rm -f $(OFILE)
