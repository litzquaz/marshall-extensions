CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -I./include
LDFLAGS = -lm

# Source files
SRCS = src/memory_forensics.c
OBJS = $(SRCS:.c=.o)

# Targets
LIB_NAME = libmemory_forensics
STATIC_LIB = $(LIB_NAME).a
SHARED_LIB = $(LIB_NAME).so

# Default target
all: $(STATIC_LIB) $(SHARED_LIB)

# Static library
$(STATIC_LIB): $(OBJS)
	ar rcs $@ $^

# Shared library
$(SHARED_LIB): $(OBJS)
	$(CC) -shared -o $@ $^ $(LDFLAGS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Clean
clean:
	rm -f $(OBJS) $(STATIC_LIB) $(SHARED_LIB)

# Install (requires sudo)
install: all
	install -d $(DESTDIR)/usr/local/lib
	install -d $(DESTDIR)/usr/local/include
	install -m 644 $(STATIC_LIB) $(DESTDIR)/usr/local/lib/
	install -m 755 $(SHARED_LIB) $(DESTDIR)/usr/local/lib/
	install -m 644 include/memory_forensics.h $(DESTDIR)/usr/local/include/
	ldconfig

# Uninstall
uninstall:
	rm -f $(DESTDIR)/usr/local/lib/$(STATIC_LIB)
	rm -f $(DESTDIR)/usr/local/lib/$(SHARED_LIB)
	rm -f $(DESTDIR)/usr/local/include/memory_forensics.h

# Test build
test: all
	$(CC) -o test_mf test/test_main.c -L. -lmemory_forensics $(LDFLAGS)
	LD_LIBRARY_PATH=. ./test_mf

.PHONY: all clean install uninstall test
