PREFIX   ?= /usr/local
BUILDDIR  = build
CFLAGS   ?=
LDFLAGS  ?=

.PHONY: all build install clean distclean reconfigure

all: build

setup:
	CFLAGS=$(CFLAGS) LDFLAGS=$(LDFLAGS) \
		meson setup $(BUILDDIR) --prefix=$(PREFIX) $(WIPE)

ifeq (,$(wildcard $(BUILDDIR)))
BUILDREQ += setup
endif

ifeq (B,$(findstring B,$(MAKEFLAGS)))
BUILDREQ += clean
endif

ifeq (1,$(if $(findstring V,$(MAKEFLAGS)),1,$(V)))
BUILDARG += --verbose
else
ifeq (1,$(V))
BUILDARG += --verbose
endif
endif

build: $(BUILDREQ)
	meson compile -C $(BUILDDIR) $(BUILDARG)

reconfigure: WIPE=--wipe
reconfigure: setup

clean:
	[ -d $(BUILDDIR) ] && meson compile -C $(BUILDDIR) --clean

distclean:
	-rm -rf $(BUILDDIR)
