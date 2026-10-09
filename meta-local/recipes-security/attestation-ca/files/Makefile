BIN     = attest_ca attest_pubkey
SRCS    = attest_ca.c
CFLAGS += -Wall -Wextra -Wshadow -Wswitch-default -I.
LDLIBS += -lteec

all: $(BIN)

attest_ca: $(SRCS) attestation_ta.h
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SRCS) $(LDLIBS)

attest_pubkey: attest_pubkey.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f $(BIN)

.PHONY: all clean
