CC = gcc
INSTALL = install
STRIP = strip
MKDIR = mkdir
PKG_CONFIG_BIN = pkg-config
PREFIX = /usr

ifneq ($(strip $(ENABLE_SANITIZER)),)
ifeq ($(strip $(ENABLE_STATIC)),)
SANITIZER_CFLAGS = -fsanitize=address -fsanitize=leak -fsanitize=undefined
endif
endif

ifneq ($(strip $(ENABLE_DEBUG)),)
DEBUG_CFLAGS = -Og -g3 -DDEBUG_BUILD
EXTRA_CFLAGS =
else
DEBUG_CFLAGS =
EXTRA_CFLAGS = -Werror -Os
endif

CFLAGS += -Wall -Wextra -std=gnu11 $(EXTRA_CFLAGS) -D_GNU_SOURCE $(DEBUG_CFLAGS) $(SANITIZER_CFLAGS) \
		 $(shell $(PKG_CONFIG_BIN) --cflags libsodium) \
		 $(shell $(PKG_CONFIG_BIN) --cflags libevent)

HEADER_TARGETS = common-event2.h common-sodium.h logging.h protocol.h
BUILD_TARGETS = common-event2.o common-sodium.o logging.o protocol.o

SO_NAME=libsodium-tcp.so
APP_HEADER_TARGETS = $(HEADER_TARGETS)
APP_BUILD_TARGETS = $(BUILD_TARGETS)

ifneq ($(strip $(ENABLE_STATIC)),)
ifneq ($(strip $(ENABLE_SHARED)),)
$(error ENABLE_STATIC and ENABLE_SHARED can not be used together!)
endif
endif

ifneq ($(strip $(ENABLE_STATIC)),)
EXTRA_CFLAGS += -static
LDFLAGS += -pthread
LIBS = $(shell $(PKG_CONFIG_BIN) --static --libs libsodium) \
       $(shell $(PKG_CONFIG_BIN) --static --libs libevent)
else
LIBS = $(shell $(PKG_CONFIG_BIN) --libs libsodium) \
       $(shell $(PKG_CONFIG_BIN) --libs libevent)
endif

ifneq ($(strip $(ENABLE_SHARED)),)
SO_TARGET=$(SO_NAME)
CFLAGS += -fPIC
LDFLAGS = -Wl,-rpath,'$$ORIGIN:$$ORIGIN/../lib'
SO_LDFLAGS = -shared
APP_HEADER_TARGETS =
APP_BUILD_TARGETS = $(SO_NAME)
endif


all: pre $(SO_TARGET) client server

pre:
	@echo "libsodium: $(shell $(PKG_CONFIG_BIN) --modversion --short-errors libsodium)"
	@echo "libevent.: $(shell $(PKG_CONFIG_BIN) --modversion --short-errors libevent)"

clean:
	rm -f $(SO_NAME) client server *.o

install: $(SO_TARGET) client server
	$(MKDIR) -p '$(DESTDIR)$(PREFIX)/bin'
ifneq ($(strip $(ENABLE_SHARED)),)
	$(MKDIR) -p '$(DESTDIR)$(PREFIX)/lib'
	$(INSTALL) --mode=0775 --strip --strip-program=$(STRIP) \
		$(SO_TARGET) '$(DESTDIR)$(PREFIX)/lib'
endif
	$(INSTALL) --mode=0775 --strip --strip-program=$(STRIP) \
		client server '$(DESTDIR)$(PREFIX)/bin'

help:
	@echo "usage:"
	@echo "make \\"
	@echo "\tENABLE_DEBUG=$(ENABLE_DEBUG) \\"
	@echo "\tENABLE_STATIC=$(ENABLE_STATIC) \\"
	@echo "\tENABLE_SANITIZER=$(ENABLE_SANITIZER) \\"
	@echo "\tBUILD_STATIC=$(BUILD_STATIC) \\"
	@echo "\tBUILD_SHARED=$(BUILD_SHARED) \\"
	@echo "\tDESTDIR=$(DESTDIR) \\"
	@echo "\tPREFIX=$(PREFIX)"
	@echo "\nphony targets: pre all install clean help"
	@echo "\nfile targets: $(SO_TARGET) client server"

%.o: %.c
	$(CC) $(CFLAGS) -c $^ -o $@

$(SO_TARGET): $(HEADER_TARGETS) $(BUILD_TARGETS)
	$(CC) $(CFLAGS) $(SO_LDFLAGS) $(BUILD_TARGETS) $(LDFLAGS) $(LIBS) -o $@
ifeq ($(strip $(ENABLE_DEBUG)),)
	$(STRIP) $@
endif

client: $(APP_HEADER_TARGETS) $(APP_BUILD_TARGETS) client.c
	$(CC) $(CFLAGS) $(APP_BUILD_TARGETS) client.c $(LDFLAGS) $(LIBS) -o $@
ifeq ($(strip $(ENABLE_DEBUG)),)
	$(STRIP) $@
endif

server: $(APP_HEADER_TARGETS) $(APP_BUILD_TARGETS) server.c
	$(CC) $(CFLAGS) $(APP_BUILD_TARGETS) server.c $(LDFLAGS) $(LIBS) -o $@
ifeq ($(strip $(ENABLE_DEBUG)),)
	$(STRIP) $@
endif

.phony: pre all install clean help
