CC=gcc
CFLAGS=-O3 -std=c99
TARGET=wild
all: $(TARGET)

$(TARGET): wildlfsr.c
	$(CC) wildlfsr.c $(CFLAGS) -o $(TARGET)

clean:
	$(RM) $(TARGET)
