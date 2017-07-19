include ../../common.mak

CFLAGS += -Os -Wall $(EXTRACFLAGS) -fPIC
CFLAGS += -I. -I$(TOP)/shared -I$(TOP)/nvram$(BCMEX) -I$(SRCBASE)/include -I$(TOP)/httpd
CFLAGS += -I$(TOP)/util-linux/include
CFLAGS += -idirafter$(LINUXDIR)/arch/arm/include -idirafter$(LINUXDIR)/include

LDFLAGS += -L$(TOP)/nvram$(BCMEX) -lnvram -L$(TOP)/shared -lshared

ifeq ($(RTCONFIG_QTN),y)
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
OBJS += iqos.o wrs.o stat.o dpi.o web_history.o wrs_app.o data_collect.o tools.o
OBJS += watchdog_check.o

# TrendMicro
OBJS += usr_ioctl.o conf_app.o

ifeq ($(RTCONFIG_BCMARM),y)
vpath %.c $(SRCBASE)/shared
endif

ifeq ($(wildcard $(SRCBASE)/router/bwdpi_dep/bwdpi/*.c),)
all:
	-cp -f prebuilt/libbwdpi.so libbwdpi.so
	-cp -f prebuilt/wrs wrs
	-cp -f prebuilt/bwdpi.h bwdpi.h
	-cp -f prebuilt/fake_cmd fake_cmd
else
all: libbwdpi.so wrs fake_cmd
endif

libbwdpi.so: $(OBJS)
	@echo " [bwdpi] LD $@"
	@$(LD) $(LD2) -shared -o $@ $^

wrs: wrs_main.o libbwdpi.so
	@$(CC) $(CFLAGS) $(LD2) -L. -lbwdpi -lgcc_s -o $@ $^

# debug usage
#wrs: wrs_main.o $(OBJS)
#	@$(CC) $(CFLAGS) $(LD2) -L. -lgcc_s -o $@ $^

fake_cmd: fake_cmd.o
ifeq ($(RTCONFIG_QCA),y)
	@$(CC) $(CFLAGS) $(LD2) -L. -lgcc_s -o $@ $^
endif

install: all
	@echo "[bwdpi] Installing..."
	@install -d $(INSTALLDIR)/bwdpi_dep/usr/lib
	@install -m 755 libbwdpi.so $(INSTALLDIR)/bwdpi_dep/usr/lib
	@$(STRIP) $(INSTALLDIR)/bwdpi_dep/usr/lib/libbwdpi.so
	@install -d $(INSTALLDIR)/bwdpi_dep/usr/sbin
	@install -m 755 wrs $(INSTALLDIR)/bwdpi_dep/usr/sbin
	@$(STRIP) $(INSTALLDIR)/bwdpi_dep/usr/sbin/wrs
ifeq ($(RTCONFIG_QCA),y)
	@install -m 755 fake_cmd $(INSTALLDIR)/bwdpi_dep/usr/sbin
	@$(STRIP) $(INSTALLDIR)/bwdpi_dep/usr/sbin/fake_cmd
	@cd $(INSTALLDIR)/bwdpi_dep/usr/sbin/ && ln -sf fake_cmd wl
endif

%.o: %.c
	@echo " [bwdpi] CC $@"
	@$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.so *.o wrs fake_cmd
