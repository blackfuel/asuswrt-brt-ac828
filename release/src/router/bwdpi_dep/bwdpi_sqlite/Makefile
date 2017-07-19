include ../../common.mak

CFLAGS += -Os -Wall $(EXTRACFLAGS) -fPIC
CFLAGS += -I. -I$(TOP)/shared -I$(SRCBASE)/include -I$(TOP)/sqlite -I$(TOP)/bwdpi_dep/bwdpi -I$(TOP)/rc -I$(TOP)/httpd
CFLAGS += -I$(TOP)/util-linux/include
CFLAGS += -idirafter$(LINUXDIR)/arch/arm/include -idirafter$(LINUXDIR)/include

LDFLAGS += -L$(TOP)/nvram$(BCMEX) -lnvram -L$(TOP)/shared -lshared
LDFLAGS += -L$(TOP)/bwdpi_dep/bwdpi -lbwdpi
LDFLAGS += -L$(TOP)/sqlite/.libs -lsqlite3

ifeq ($(RTCONFIG_QTN),y)
CFLAGS += -I$(TOP)/libqcsapi_client
LDFLAGS += -L$(TOP)/libqcsapi_client -lqcsapi_client
endif

ifeq ($(RTCONFIG_PERMISSION_MANAGEMENT),y)
CFLAGS += -I$(TOP)/sqlCipher
CFLAGS += -I$(TOP)/PMS_DBapis
CFLAGS += -I$(TOP)/openssl/include/openssl
LDFLAGS += -L$(TOP)/openssl -lcrypto -lssl
LDFLAGS += -L $(TOP)/sqlCipher/.libs -lsqlcipher
LDFLAGS += -L$(TOP)/PMS_DBapis -lpms_sql
endif

# for QCA toolchain compile issue, xxxx-ld has no pthead and dl in openwrt-toolchain
ifeq ($(RTCONFIG_QCA),y)
EXTRACC += -lpthread -ldl
EXTRALD =
else
EXTRACC += -lpthread
EXTRALD += -lpthread
endif

LD1 += $(LDFLAGS) $(EXTRACC)
LD2 += $(LDFLAGS) $(EXTRALD)

# ASUSWRT
OBJS += main.o table.o sqlite_stat.o

ifeq ($(RTCONFIG_BCMARM),y)
vpath %.c $(SRCBASE)/shared
endif

ifeq ($(wildcard $(SRCBASE)/router/bwdpi_dep/bwdpi_sqlite/*.c),)
all:
	-cp -f prebuilt/bwdpi_sqlite bwdpi_sqlite
	-cp -f prebuilt/libbwdpi_sql.so libbwdpi_sql.so
else
all: bwdpi_sqlite libbwdpi_sql.so
endif

bwdpi_sqlite: $(OBJS)
	@echo " [bwdpi_sqlite] CC $@"
	@$(CC) -o $@ $^ $(LD1)
	@$(STRIP) bwdpi_sqlite

libbwdpi_sql.so: sqlite_stat.o
	@echo " [bwdpi] LD $@"
	@$(LD) $(LD2) -shared -o $@ $^

install: all
	@echo "[bwdpi_sqlite] Installing..."
	@install -D bwdpi_sqlite $(INSTALLDIR)/bwdpi_dep/sbin/bwdpi_sqlite
	@$(STRIP) $(INSTALLDIR)/bwdpi_dep/sbin/bwdpi_sqlite
	@install -d $(INSTALLDIR)/bwdpi_dep/usr/lib
	@install -m 755 libbwdpi_sql.so $(INSTALLDIR)/bwdpi_dep/usr/lib
	@$(STRIP) $(INSTALLDIR)/bwdpi_dep/usr/lib/libbwdpi_sql.so

%.o: %.c
	@echo " [bwdpi_sqlite] CC $@"
	@$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o bwdpi_sqlite libbwdpi_sql.so
