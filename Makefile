CC=g++
CFLAGS=-c -Wall
LDFLAGS=-lpcap -lcurses
SRCDIR=src
EXEDIR=build
SOURCES=$(wildcard $(SRCDIR)/*.cpp)
EXECUTABLE=$(EXEDIR)/arp

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(SOURCES)
	$(CC) $(SOURCES) $(LDFLAGS) -o $@

clean:
	rm -rf $(EXECUTABLE) $(SRCDIR)/*.o $(EXEDIR)/*.o