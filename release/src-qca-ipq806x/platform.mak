export LINUXDIR := $(SRCBASE)/linux/linux-3.4.x

ifeq ($(EXTRACFLAGS),)
export EXTRACFLAGS := -DBCMWPA2 -fno-delete-null-pointer-checks -marm -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=softfp
endif

export BUILD := $(shell (gcc -dumpmachine))
export KERNEL_BINARY=$(LINUXDIR)/vmlinux
export PLATFORM := arm-uclibc
export CROSS_COMPILE := arm-openwrt-linux-uclibcgnueabi-
export CROSS_COMPILER := $(CROSS_COMPILE)
export READELF := arm-openwrt-linux-uclibcgnueabi-readelf
export CONFIGURE := ./configure --host=arm-linux --build=$(BUILD)
export HOSTCONFIG := linux-armv4
export ARCH := arm
export HOST := arm-linux
export KERNELCC := $(CROSS_COMPILE)gcc
export KERNELLD := $(CROSS_COMPILE)ld
export TOOLS := /opt/openwrt-gcc463.arm
export RTVER := 0.9.33.2

# Kernel load address and entry address
export LOADADDR := 41508000
export ENTRYADDR := $(LOADADDR)

# OpenWRT's toolchain needs STAGING_DIR environment variable that points to top directory of toolchain.
export STAGING_DIR=$(shell which arm-openwrt-linux-gcc|sed -e "s,/bin/arm-openwrt-linux-gcc,,")

EXTRA_CFLAGS := -DLINUX26 -DCONFIG_QCA -pipe -DDEBUG_NOISY -DDEBUG_RCTEST -march=armv7-a -mfpu=vfpv3-d16 -mfloat-abi=softfp

export CONFIG_LINUX26=y
export CONFIG_QCA=y

EXTRA_CFLAGS += -DLINUX30
export CONFIG_LINUX30=y

SWITCH_CHIP_ID_POOL =			\
	"QCA8337N"			\
	"RTL8370M_PHY_QCA8033_X2"	\
	"RTL8370MB_PHY_QCA8033_X2"

define platformRouterOptions
	@( \
	if [ "$(QCA)" = "y" ]; then \
		sed -i "/RTCONFIG_QCA\>/d" $(1); \
		echo "RTCONFIG_QCA=y" >>$(1); \
		if [ "$(IPQ806X)" = "y" ] ; then \
			sed -i "/RTCONFIG_SOC_IPQ8064/d" $(1); \
			echo "RTCONFIG_SOC_IPQ8064=y" >>$(1); \
		fi; \
		if [ "$(WIFI_CHIP)" = "BEELINER" ] ; then \
			sed -i "/RTCONFIG_WIFI_QCA9990_QCA9990/d" $(1); \
			echo "RTCONFIG_WIFI_QCA9990_QCA9990=y" >>$(1); \
			sed -i "/RTCONFIG_VHT80_80/d" $(1); \
			echo "RTCONFIG_VHT80_80=y" >>$(1); \
			sed -i "/RTCONFIG_VHT160/d" $(1); \
			echo "RTCONFIG_VHT160=y" >>$(1); \
		fi; \
		if [ "$(WIFI_CHIP)" = "CASCADE" ] ; then \
			sed -i "/RTCONFIG_WIFI_QCA9994_QCA9994/d" $(1); \
			echo "RTCONFIG_WIFI_QCA9994_QCA9994=y" >>$(1); \
			sed -i "/RTCONFIG_VHT80_80/d" $(1); \
			echo "RTCONFIG_VHT80_80=y" >>$(1); \
			sed -i "/RTCONFIG_VHT160/d" $(1); \
			echo "RTCONFIG_VHT160=y" >>$(1); \
		fi; \
		for chip in $(SWITCH_CHIP_ID_POOL) ; do \
			sed -i "/RTCONFIG_SWITCH_$${chip}\>/d" $(1); \
			if [ "$(SWITCH_CHIP)" = "$${chip}" ] ; then \
				echo "RTCONFIG_SWITCH_$${chip}=y" >> $(1); \
			else \
				echo "# RTCONFIG_SWITCH_$${chip} is not set" >> $(1); \
			fi; \
		done; \
		if [ "$(TEST_BDF)" = "y" ]; then \
			sed -i "/RTCONFIG_TEST_BOARDDATA_FILE/d" $(1); \
			echo "RTCONFIG_TEST_BOARDDATA_FILE=y" >>$(1); \
		fi; \
		if [ "$(NSS_IPSEC)" = "y" ]; then \
			sed -i "/RTCONFIG_NSS_IPSEC/d" $(1); \
			echo "RTCONFIG_NSS_IPSEC=y" >>$(1); \
		fi; \
	fi; \
	)
endef

define platformBusyboxOptions
	@( \
	if [ "$(QCA)" = "y" ]; then \
		sed -i "/CONFIG_FEATURE_TOP_SMP_CPU/d" $(1); \
		echo "CONFIG_FEATURE_TOP_SMP_CPU=y" >>$(1); \
		sed -i "/CONFIG_FEATURE_TOP_DECIMALS/d" $(1); \
		echo "CONFIG_FEATURE_TOP_DECIMALS=y" >>$(1); \
		sed -i "/CONFIG_FEATURE_TOP_SMP_PROCESS/d" $(1); \
		echo "CONFIG_FEATURE_TOP_SMP_PROCESS=y" >>$(1); \
		sed -i "/CONFIG_FEATURE_TOPMEM/d" $(1); \
		echo "CONFIG_FEATURE_TOPMEM=y" >>$(1); \
		sed -i "/CONFIG_FEATURE_SHOW_THREADS/d" $(1); \
		echo "CONFIG_FEATURE_SHOW_THREADS=y" >>$(1); \
	fi; \
	)
endef

define platformKernelConfig
	@( \
	if [ "$(QCA)" = "y" ]; then \
		if [ "$(IPQ806X)" = "y" ] ; then \
			sed -i "/CONFIG_BRIDGE_NETFILTER/d" $(1); \
			echo "CONFIG_BRIDGE_NETFILTER=y" >>$(1); \
		fi; \
		sed -i "/CONFIG_NETFILTER_XT_MATCH_PHYSDEV/d" $(1); \
		echo "CONFIG_NETFILTER_XT_MATCH_PHYSDEV=y" >>$(1); \
		if [ "$(CONFIG_LINUX30)" = "y" ]; then \
			if [ "$(BOOT_FLASH_TYPE)" = "SPI" ] ; then \
				sed -i "/CONFIG_MTD_MSM_NAND\>/d" $(1); \
				echo "# CONFIG_MTD_MSM_NAND is not set" >> $(1); \
				sed -i "/CONFIG_MTD_M25P80\>/d" $(1); \
				echo "CONFIG_MTD_M25P80=y" >> $(1); \
				sed -i "/CONFIG_SPI_QUP\>/d" $(1); \
				echo "CONFIG_SPI_QUP=y" >> $(1); \
			else \
				sed -i "/CONFIG_MTD_MSM_NAND\>/d" $(1); \
				echo "CONFIG_MTD_MSM_NAND=y" >> $(1); \
				sed -i "/CONFIG_MTD_M25P80\>/d" $(1); \
				echo "# CONFIG_MTD_M25P80 is not set" >> $(1); \
			fi; \
			sed -i "/CONFIG_BRIDGE_EBT_ARPNAT/d" $(1); \
			echo "# CONFIG_BRIDGE_EBT_ARPNAT is not set" >>$(1); \
			sed -i "/CONFIG_NF_CONNTRACK_EVENTS/d" $(1); \
			echo "CONFIG_NF_CONNTRACK_EVENTS=y" >>$(1); \
			sed -i "/CONFIG_NF_CONNTRACK_CHAIN_EVENTS/d" $(1); \
			echo "# CONFIG_NF_CONNTRACK_CHAIN_EVENTS is not set" >>$(1); \
		fi; \
		if [ "$(RTAC88N)" = "y" ] ; then \
			sed -i "/CONFIG_MACH_IPQ806X_AP148\>/d" $(1); \
			echo "CONFIG_MACH_IPQ806X_AP148=y" >>$(1); \
			sed -i "/CONFIG_MACH_IPQ806X_AP161/d" $(1); \
			echo "CONFIG_MACH_IPQ806X_AP161=y" >>$(1); \
			sed -i "/CONFIG_QCA_AP148/d" $(1); \
			echo "CONFIG_QCA_AP148=y" >>$(1); \
			sed -i "/CONFIG_ASUS_BRTAC828/d" $(1); \
			echo "# CONFIG_ASUS_BRTAC828 is not set" >>$(1); \
		fi; \
		if [ "$(BRTAC828)" = "y" ] || [ "$(RTAC88S)" = "y" ] ; then \
			sed -i "/CONFIG_QCA_AP148/d" $(1); \
			echo "# CONFIG_QCA_AP148 is not set" >>$(1); \
			sed -i "/CONFIG_ASUS_BRTAC828/d" $(1); \
			echo "CONFIG_ASUS_BRTAC828=y" >>$(1); \
			sed -i "/CONFIG_SERIAL_MSM_HS_GSBI2/d" $(1); \
			echo "CONFIG_SERIAL_MSM_HS_GSBI2=y" >>$(1); \
		fi; \
		if [ "$(SWITCH_CHIP)" = "RTL8370M_PHY_QCA8033_X2" ] ; then \
			sed -i "/CONFIG_AR8033_PHY/d" $(1); \
			echo "CONFIG_AR8033_PHY=y" >>$(1); \
		fi; \
		for chip in $(SWITCH_CHIP_ID_POOL) ; do \
			sed -i "/CONFIG_SWITCH_$${chip}\>/d" $(1); \
			if [ "$(SWITCH_CHIP)" = "$${chip}" ] ; then \
				echo "CONFIG_SWITCH_$${chip}=y" >> $(1); \
			else \
				echo "# CONFIG_SWITCH_$${chip} is not set" >> $(1); \
			fi; \
		done; \
		if [ "$(WIFI_CHIP)" = "BEELINER" ] ; then \
			sed -i "/CONFIG_ETHERNET/d" $(1); \
			echo "# CONFIG_ETHERNET is not set" >>$(1); \
			sed -i "/CONFIG_MDIO\>/d" $(1); \
			echo "# CONFIG_MDIO is not set" >>$(1); \
		fi; \
		if [ "$(WIFI_CHIP)" = "CASCADE" ] ; then \
			sed -i "/CONFIG_ETHERNET/d" $(1); \
			echo "CONFIG_ETHERNET=y" >>$(1); \
			sed -i "/CONFIG_MDIO\>/d" $(1); \
			echo "CONFIG_MDIO=y" >>$(1); \
			sed -i "/CONFIG_IP_MROUTE_MULTIPLE_TABLES\>/d" $(1); \
			echo "CONFIG_IP_MROUTE_MULTIPLE_TABLES=y" >>$(1); \
			sed -i "/CONFIG_KEYS\>/d" $(1); \
			echo "CONFIG_KEYS=y" >>$(1); \
			sed -i "/CONFIG_ASYMMETRIC_KEY_TYPE\>/d" $(1); \
			echo "CONFIG_ASYMMETRIC_KEY_TYPE=y" >>$(1); \
			sed -i "/CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE\>/d" $(1); \
			echo "CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y" >>$(1); \
			sed -i "/CONFIG_PUBLIC_KEY_ALGO_RSA\>/d" $(1); \
			echo "CONFIG_PUBLIC_KEY_ALGO_RSA=y" >>$(1); \
			sed -i "/CONFIG_X509_CERTIFICATE_PARSER\>/d" $(1); \
			echo "CONFIG_X509_CERTIFICATE_PARSER=y" >>$(1); \
			sed -i "/CONFIG_FW_AUTH\>/d" $(1); \
			echo "CONFIG_FW_AUTH=y" >>$(1); \
		fi; \
	fi; \
	if [ "$(JFFS2)" = "y" ]; then \
		if [ "$(CONFIG_LINUX26)" = "y" ]; then \
			sed -i "/CONFIG_JFFS2_FS/d" $(1); \
			echo "CONFIG_JFFS2_FS=m" >>$(1); \
			sed -i "/CONFIG_JFFS2_FS_DEBUG/d" $(1); \
			echo "CONFIG_JFFS2_FS_DEBUG=0" >>$(1); \
			sed -i "/CONFIG_JFFS2_FS_WRITEBUFFER/d" $(1); \
			echo "CONFIG_JFFS2_FS_WRITEBUFFER=y" >>$(1); \
			sed -i "/CONFIG_JFFS2_SUMMARY/d" $(1); \
			echo "# CONFIG_JFFS2_SUMMARY is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_FS_XATTR/d" $(1); \
			echo "# CONFIG_JFFS2_FS_XATTR is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_COMPRESSION_OPTIONS/d" $(1); \
			echo "CONFIG_JFFS2_COMPRESSION_OPTIONS=y" >>$(1); \
			sed -i "/CONFIG_JFFS2_ZLIB/d" $(1); \
			echo "CONFIG_JFFS2_ZLIB=y" >>$(1); \
			sed -i "/CONFIG_JFFS2_LZO/d" $(1); \
			echo "# CONFIG_JFFS2_LZO is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_LZMA/d" $(1); \
			echo "# CONFIG_JFFS2_LZMA is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_RTIME/d" $(1); \
			echo "# CONFIG_JFFS2_RTIME is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_RUBIN/d" $(1); \
			echo "# CONFIG_JFFS2_RUBIN is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_CMODE_NONE/d" $(1); \
			echo "# CONFIG_JFFS2_CMODE_NONE is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_CMODE_PRIORITY/d" $(1); \
			echo "CONFIG_JFFS2_CMODE_PRIORITY=y" >>$(1); \
			sed -i "/CONFIG_JFFS2_CMODE_SIZE/d" $(1); \
			echo "# CONFIG_JFFS2_CMODE_SIZE is not set" >>$(1); \
		fi; \
		if [ "$(CONFIG_LINUX30)" = "y" ]; then \
			sed -i "/CONFIG_JFFS2_FS_WBUF_VERIFY/d" $(1); \
			echo "# CONFIG_JFFS2_FS_WBUF_VERIFY is not set" >>$(1); \
			sed -i "/CONFIG_JFFS2_CMODE_FAVOURLZO/d" $(1); \
			echo "# CONFIG_JFFS2_CMODE_FAVOURLZO is not set" >>$(1); \
		fi; \
	else \
		sed -i "/CONFIG_JFFS2_FS/d" $(1); \
		echo "# CONFIG_JFFS2_FS is not set" >>$(1); \
	fi; \
	if [ "$(UBI)" = "y" ]; then \
		sed -i "/CONFIG_MTD_UBI\>/d" $(1); \
		echo "CONFIG_MTD_UBI=y" >>$(1); \
		sed -i "/CONFIG_MTD_UBI_WL_THRESHOLD/d" $(1); \
		echo "CONFIG_MTD_UBI_WL_THRESHOLD=4096" >>$(1); \
		sed -i "/CONFIG_MTD_UBI_BEB_RESERVE/d" $(1); \
		echo "CONFIG_MTD_UBI_BEB_RESERVE=1" >>$(1); \
		sed -i "/CONFIG_MTD_UBI_GLUEBI/d" $(1); \
		echo "CONFIG_MTD_UBI_GLUEBI=y" >>$(1); \
		sed -i "/CONFIG_FACTORY_CHECKSUM/d" $(1); \
		echo "CONFIG_FACTORY_CHECKSUM=y" >>$(1); \
		if [ "$(UBI_DEBUG)" = "y" ]; then \
			sed -i "/CONFIG_MTD_UBI_DEBUG/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG=y" >>$(1); \
			sed -i "/CONFIG_GCOV_KERNEL/d" $(1); \
			echo "# CONFIG_GCOV_KERNEL is not set" >>$(1); \
			sed -i "/CONFIG_L2TP_DEBUGFS/d" $(1); \
			echo "# CONFIG_L2TP_DEBUGFS is not set" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_MSG/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_MSG=y" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_PARANOID/d" $(1); \
			echo "# CONFIG_MTD_UBI_DEBUG_PARANOID is not set" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_DISABLE_BGT/d" $(1); \
			echo "# CONFIG_MTD_UBI_DEBUG_DISABLE_BGT is not set" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_EMULATE_BITFLIPS/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_EMULATE_BITFLIPS=y" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_EMULATE_WRITE_FAILURES/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_EMULATE_WRITE_FAILURES=y" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_EMULATE_ERASE_FAILURES/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_EMULATE_ERASE_FAILURES=y" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_MSG_BLD/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_MSG_BLD=y" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_MSG_EBA/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_MSG_EBA=y" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_MSG_WL/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_MSG_WL=y" >>$(1); \
			sed -i "/CONFIG_MTD_UBI_DEBUG_MSG_IO/d" $(1); \
			echo "CONFIG_MTD_UBI_DEBUG_MSG_IO=y" >>$(1); \
			sed -i "/CONFIG_JBD_DEBUG/d" $(1); \
			echo "# CONFIG_JBD_DEBUG is not set" >>$(1); \
			sed -i "/CONFIG_LKDTM/d" $(1); \
			echo "# CONFIG_LKDTM is not set" >>$(1); \
			sed -i "/CONFIG_DYNAMIC_DEBUG/d" $(1); \
			echo "CONFIG_DYNAMIC_DEBUG=y" >>$(1); \
			sed -i "/CONFIG_SPINLOCK_TEST/d" $(1); \
			echo "# CONFIG_SPINLOCK_TEST is not set" >>$(1); \
		else \
			sed -i "/CONFIG_MTD_UBI_DEBUG/d" $(1); \
			echo "# CONFIG_MTD_UBI_DEBUG is not set" >>$(1); \
		fi; \
		if [ "$(UBIFS)" = "y" ]; then \
			sed -i "/CONFIG_UBIFS_FS/d" $(1); \
			echo "CONFIG_UBIFS_FS=y" >>$(1); \
			sed -i "/CONFIG_UBIFS_FS_XATTR/d" $(1); \
			echo "# CONFIG_UBIFS_FS_XATTR is not set" >>$(1); \
			sed -i "/CONFIG_UBIFS_FS_ADVANCED_COMPR/d" $(1); \
			echo "CONFIG_UBIFS_FS_ADVANCED_COMPR=y" >>$(1); \
			sed -i "/CONFIG_UBIFS_FS_LZO/d" $(1); \
			echo "CONFIG_UBIFS_FS_LZO=y" >>$(1); \
			sed -i "/CONFIG_UBIFS_FS_ZLIB/d" $(1); \
			echo "CONFIG_UBIFS_FS_ZLIB=y" >>$(1); \
			sed -i "/CONFIG_UBIFS_FS_XZ/d" $(1); \
			echo "CONFIG_UBIFS_FS_XZ=y" >>$(1); \
			sed -i "/CONFIG_UBIFS_FS_DEBUG/d" $(1); \
			echo "# CONFIG_UBIFS_FS_DEBUG is not set" >>$(1); \
		else \
			sed -i "/CONFIG_UBIFS_FS/d" $(1); \
			echo "# CONFIG_UBIFS_FS is not set" >>$(1); \
		fi; \
		if [ "$(DUMP_OOPS_MSG)" = "y" ]; then \
			echo "CONFIG_DUMP_PREV_OOPS_MSG=y" >>$(1); \
			echo "CONFIG_DUMP_PREV_OOPS_MSG_BUF_ADDR=0x45300000" >>$(1); \
			echo "CONFIG_DUMP_PREV_OOPS_MSG_BUF_LEN=0x2000" >>$(1); \
		fi; \
	fi; \
	)
endef
