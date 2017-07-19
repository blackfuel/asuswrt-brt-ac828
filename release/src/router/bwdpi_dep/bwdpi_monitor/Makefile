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
OBJS += AiProtectionMonitor.o AiProtectionMonitor_hook.o

ifeq ($(RTCONFIG_BCMARM),y)
vpath %.c $(SRCBASE)/shared
endif

ifeq ($(wildcard $(SRCBASE)/router/bwdpi_dep/bwdpi_monitor/*.c),)
all:
	-cp -f prebuilt/libbwdpi_monitor.so libbwdpi_monitor.so
	-cp -f prebuilt/AiProtectionMonitor AiProtectionMonitor
else
all: AiProtectionMonitor libbwdpi_monitor.so
endif

AiProtectionMonitor: $(OBJS)
	@echo " [bwdpi_monitor] CC $@"
	@$(CC) -o $@ $^ $(LD1)
	@$(STRIP) AiProtectionMonitor

libbwdpi_monitor.so : AiProtectionMonitor_hook.o
	@echo " [bwdpi_monitor] LD $@"
	@$(LD) $(LD2) -shared -o $@ $^

install: all
	@echo "[bwdpi_monitor] Installing..."
	@install -D AiProtectionMonitor $(INSTALLDIR)/bwdpi_dep/usr/sbin/AiProtectionMonitor
	@$(STRIP) $(INSTALLDIR)/bwdpi_dep/usr/sbin/AiProtectionMonitor
	@install -m 755 libbwdpi_monitor.so $(INSTALLDIR)/bwdpi_dep/usr/lib
	@$(STRIP) $(INSTALLDIR)/bwdpi_dep/usr/lib/libbwdpi_monitor.so 

%.o: %.c
	@echo " [bwdpi_monitor] CC $@"
	@$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o AiProtectionMonitor libbwdpi_monitor.so
