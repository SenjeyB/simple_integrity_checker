CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -static -l:libssl.a -l:libcrypto.a -ldl -lpthread
TARGET = main
SRC = main.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
