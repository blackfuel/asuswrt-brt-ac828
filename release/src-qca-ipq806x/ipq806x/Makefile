#
# Platform specific router Makefile
#
# Copyright 2016, Broadcom
# All Rights Reserved.
#
# THIS SOFTWARE IS OFFERED "AS IS", AND BROADCOM GRANTS NO WARRANTIES OF ANY
# KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
# SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
#
#

include ../router/common.mak
include $(SRCBASE)/.config

export CFLAGS+=$(EXTRACFLAGS)
export LDFLAGS+=$(EXTRALDFLAGS)

# Package dependence
PKGDEP_IW		:= libnl-tiny
PKGDEP_IWINFO		:= iw libnl-tiny qca-wifi
PKGDEP_QCA_BACKPORTS	:= wigig-firmware qca-nss-drv
PKGDEP_QCA_NSS_CFI	:= qca-nss-crypto
PKGDEP_QCA_NSS_CLIENT	:= qca-nss-drv qca-nss-crypto nat46
PKGDEP_QCA_NSS_CRYPTO	:= qca-nss-drv
PKGDEP_QCA_NSS_DRV	:= qca-nss-gmac
# If ECM_CLASSIFIER_HYFI_ENABLE is enabled, qca-hyfi-bridge has to be build prior qca-nss30-ecm
PKGDEP_QCA_NSS_ECM	:= qca-nss-drv shortcut-fe nat46 $(if $(CONFIG_SWITCH_QCA8337N),qca-mcs-lkm)
PKGDEP_QCA_HOSTAP	:= qca-wifi libnl-bf openssl
PKGDEP_QCA_SHORTCUT_FE	:= libnl-bf
PKGDEP_QCA_WIFI		:= qca-nss-drv iproute2-3.x
PKGDEP_QCA_WHC_LBD	:= libqcacommon

#
# software package selection
#
pobj-y:=

# IPQ8064.ILQ 3.1
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-wifi $(PKGDEP_QCA_WIFI)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-wifi-fw
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qcmbr
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-hostap $(PKGDEP_QCA_HOSTAP)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += $(if $(RTCONFIG_SWITCH_QCA8337N),qca-mcs-lkm)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-fw
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-drv $(PKGDEP_QCA_NSS_DRV)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-gmac
#pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-macsec	# need IPQ8066, IPQ8068
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-ecm $(PKGDEP_QCA_NSS_ECM)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-crypto $(PKGDEP_QCA_NSS_CRYPTO)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-cfi $(PKGDEP_QCA_NSS_CFI)	# need kmod-crypto-ocf
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-nss-clients $(PKGDEP_QCA_NSS_CLIENT)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-thermald
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += shortcut-fe $(PKGDEP_QCA_SHORTCUT_FE)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-whc-lbd $(PKGDEP_QCA_WHC_LBD)

ifeq ($(SWITCH_CHIP),QCA8337N)
pobj-$(RTCONFIG_WIFI_QCA9994_QCA9994) += qca-ssdk
endif

# IPQ8064.ILQ 1.3.7
pobj-$(RTCONFIG_WIGIG) += qca-backports wigig-firmware $(PKGDEP_QCA_BACKPORTS)
pobj-$(RTCONFIG_WIGIG) += iw $(PKGDEP_IW)
pobj-$(RTCONFIG_WIGIG) += iwinfo $(PKGDEP_IWINFO)


pobj-clean := $(foreach pobj, $(pobj-y) $(pobj-n) $(pobj-), $(pobj)-clean)
pobj-install := $(foreach pobj,$(pobj-y),$(pobj)-install)

#
# Basic rules
#

all: $(pobj-y)

install: $(pobj-install) gen_target

gen_target:
	[ -d $(TARGETDIR) ] || install -d $(TARGETDIR)
	for dir in $(wildcard $(patsubst %,$(INSTALLDIR)/%,$(pobj-y))) ; do \
		(cd $${dir} && tar cpf - .) | (cd $(TARGETDIR) && tar xpf -) \
	done

clean: $(pobj-clean)

distclean: clean

#
# include rules for platform specific software packages
#
-include $(wildcard mak/*.mak)

#
# configuration
#

#
# overrides and extra dependencies
#

#
# Generic rules
#

%:
	@[ ! -d $* ] || [ -f $*/Makefile ] || $(MAKE) $*-configure
	@[ ! -d $* ] || ( $(MAKE) -C $* )


%-clean:
	-@[ ! -d $* ] || $(MAKE) -C $* clean


%-install: %
	@echo $*
	@[ ! -d $* ] || $(MAKE) -C $* install INSTALLDIR=$(INSTALLDIR)/$*

%-stage:
	@echo $*
	@[ ! -d $* ] || $(MAKE) -C $* install DESTDIR=$(STAGEDIR) INSTALLDIR=$(INSTALLDIR)/$*

%-build:
	$(MAKE) $*-clean $*

%/Makefile:
	[ ! -d $* ] || $(MAKE) $*-configure

%-configure:
	@[ ! -d $* ] || ( cd $* ; \
		$(CONFIGURE) \
		--prefix=/usr \
		--bindir=/usr/sbin \
		--libdir=/usr/lib \
	)


$(pobj-y) $(pobj-n) $(pobj-clean) $(pobj-install): dummy

.PHONY: all clean distclean mrproper install package image
.PHONY: conf mconf oldconf kconf kmconf config menuconfig oldconfig
.PHONY: dummy libnet libpcap


