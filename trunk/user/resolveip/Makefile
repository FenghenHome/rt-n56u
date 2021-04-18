ifndef ROOTDIR
ROOTDIR=../..
endif

CFLAGS  += -ffunction-sections -fdata-sections -fvisibility=hidden
LDFLAGS += -Wl,--gc-sections

SHDIR		= $(ROOTDIR)/user/shared
CFLAGS		+= -I$(SHDIR)
LDFLAGS		+= -L$(SHDIR) -lshared

all:
	$(CC) $(CFLAGS) $(LDFLAGS) resolveip.c -o resolveip

clean:
	rm -f resolveip

romfs:
	$(ROMFSINST) resolveip /usr/bin/resolveip

