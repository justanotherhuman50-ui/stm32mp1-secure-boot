BIN     = attest_ca
SRCS    = attest_ca.c
CFLAGS += -Wall -Wextra -Wshadow -Wswitch-default -I.
LDLIBS += -lteec

all: $(BIN)

$(BIN): $(SRCS) attestation_ta.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(LDLIBS)

clean:
	rm -f $(BIN)

.PHONY: all clean
