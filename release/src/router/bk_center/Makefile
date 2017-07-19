include ../common.mak

CFLAGS += -Os -Wall $(EXTRACFLAGS) -I. -I$(TOP)/shared -I$(TOP)/nvram$(BCMEX) -I$(SRCBASE)/include
CFLAGS += -I$(TOP)/libdisk -fPIC


LDFLAGS += -L$(TOP)/nvram$(BCMEX) -lnvram -L$(TOP)/shared -lshared
LDFLAGS += -L$(TOP)/libdisk -ldisk

BK_OBJS += webmon_usb.o bk_center.o
JFFS_OBJS += webmon_usb.o webmon_jffs.o

ifeq ($(wildcard $(SRCBASE)/router/bk_center/*.c),)
all:
	-cp -f prebuild/libbk_center.so libbk_center.so
	-cp -f prebuild/libwebmon_jffs.so libwebmon_jffs.so
else
all: libbk_center.so libwebmon_jffs.so
endif

libbk_center.so: $(BK_OBJS)
	@$(LD) $(LDFLAGS) -shared -o $@ $^

libwebmon_jffs.so: $(JFFS_OBJS)
	@$(CC) $(LDFLAGS) -shared -o $@ $^

install: all
	@echo "[bwdpi] Installing..."
	@install -d $(INSTALLDIR)/bk_center/usr/lib
	@install -m 755 bk_center.so $(INSTALLDIR)/bk_center/usr/lib
	@install -m 755 webmon_jffs.so $(INSTALLDIR)/bk_center/usr/lib
	@cp -f *.so $(TARGETDIR)/usr/lib/

%.o: %.c
	@echo "[bk_center] CC $@"
	@$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o *.so
