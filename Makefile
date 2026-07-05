CC = gcc
CFLAGS = -Wall -Wextra -O2
LDLIBS = -lpcap
TARGET = pcap_sniffer
SRCS = pcap_sniffer.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) myheader.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(TARGET)
