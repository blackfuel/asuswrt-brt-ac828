#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bcmnvram.h>
#include <bcmdevs.h>
#include <shutils.h>
#include <shared.h>
#include <rtstate.h>

/* keyword for rc_support 	*/
/* ipv6 mssid update parental 	*/

void add_rc_support(char *feature)
{
	char *rcsupport = nvram_safe_get("rc_support");
	char *features;

	if (!(feature && *feature))
		return;

	if (*rcsupport) {
		features = malloc(strlen(rcsupport) + strlen(feature) + 2);
		if (features == NULL) {
			_dprintf("add_rc_support fail\n");
			return;
		}
		sprintf(features, "%s %s", rcsupport, feature);
		nvram_set("rc_support", features);
		free(features);
	} else
		nvram_set("rc_support", feature);
}

#if defined(RTCONFIG_DUALWAN)
/**
 * is_nat_enabled() for dual/multiple WAN.
 * In Single WAN mode or Dual WAN Fail-Over/Fail-Back mode, check primary WAN.
 * In Dual WAN load-balance mode, check all WAN.
 */
int is_nat_enabled(void)
{
	int i, nr_nat = 0, sw_mode = nvram_get_int("sw_mode");
	char prefix[sizeof("wanX_XXXXXX")];

	if (sw_mode != SW_MODE_ROUTER && sw_mode != SW_MODE_HOTSPOT)
		return 0;

	if (get_nr_wan_unit() >= 2 && nvram_match("wans_mode", "lb")) {
		/* Dual WAN LB, check all WAN unit. */
		for (i = WAN_UNIT_FIRST; i < WAN_UNIT_MAX; ++i) {
			snprintf(prefix, sizeof(prefix), "wan%d_", i);
			if (nvram_pf_get_int(prefix, "nat_x") == 1)
				nr_nat++;
		}
	} else {
		/* Single WAN/Dual WAN FO/FB, check primary WAN unit only. */
		snprintf(prefix, sizeof(prefix), "wan%d_", wan_primary_ifunit());
		nr_nat = nvram_pf_get_int(prefix, "nat_x");
	}

	return (nr_nat > 0)? 1 : 0;
}
#endif

int get_wan_state(int unit){
	char tmp[100], prefix[16];

	snprintf(prefix, 16, "wan%d_", unit);

	return nvram_get_int(strcat_r(prefix, "state_t", tmp));
}

int get_wan_sbstate(int unit){
	char tmp[100], prefix[16];

	snprintf(prefix, 16, "wan%d_", unit);

	return nvram_get_int(strcat_r(prefix, "sbstate_t", tmp));
}

int get_wan_auxstate(int unit){
	char tmp[100], prefix[16];

	snprintf(prefix, 16, "wan%d_", unit);

	return nvram_get_int(strcat_r(prefix, "auxstate_t", tmp));
}

char *link_wan_nvname(int unit, char *buf, int size){
	if(buf == NULL)
		return NULL;

	if(unit == WAN_UNIT_FIRST)
		snprintf(buf, size, "link_wan");
	else
		snprintf(buf, size, "link_wan%d", unit);

	return buf;
}

int is_wan_connect(int unit){
	char tmp[100], prefix[]="wanXXXXXX_";
	int wan_state, wan_sbstate, wan_auxstate;

	if(!is_phy_connect(unit))
		return 0;

	snprintf(prefix, sizeof(prefix), "wan%d_", unit);

	wan_state = nvram_get_int(strcat_r(prefix, "state_t", tmp));
	wan_sbstate = nvram_get_int(strcat_r(prefix, "sbstate_t", tmp));
	wan_auxstate = nvram_get_int(strcat_r(prefix, "auxstate_t", tmp));

	if(wan_state == 2 && wan_sbstate == 0 &&
			(wan_auxstate == 0 || wan_auxstate == 2)
			)
		return 1;
	else
		return 0;
}

// auxstate will be reset by update_wan_state(), but wanduck cannot set it soon sometimes.
// only link_wan will be safe.
int is_phy_connect(int unit){
	char prefix[sizeof("link_wanXXXXXX")], *ptr;
	int link_wan;

	link_wan_nvname(unit, prefix, sizeof(prefix));

	if((ptr = nvram_get(prefix)) != NULL){
		link_wan = atoi(ptr);

		if(link_wan)
			return 1;
		else
			return 0;
	}
	else
#ifdef RTCONFIG_USB_MODEM
	if(dualwan_unit__usbif(unit))
		return 1;
	else
#endif
		return get_wanports_status(unit);
}

int is_ip_conflict(int unit){
	int wan_state, wan_sbstate;

	wan_state = get_wan_state(unit);
	wan_sbstate = get_wan_sbstate(unit);

	if(wan_state == 4 && wan_sbstate == 4)
		return 1;
	else
		return 0;
}

// get wan_unit from device ifname or hw device ifname
#if 0
int get_wan_unit(char *ifname)
{
	char word[256], tmp[100], *next;
	char prefix[32]="wanXXXXXX_";
	int unit, found = 0;

	unit = WAN_UNIT_FIRST;

	foreach (word, nvram_safe_get("wan_ifnames"), next) {
		if(strncmp(ifname, "ppp", 3)==0) {
			snprintf(prefix, sizeof(prefix), "wan%d_", unit);
			if(strcmp(nvram_safe_get(strcat_r(prefix, "pppoe_ifname", tmp)), ifname)==0) {
				found = 1;
			}	
		}
		else if(strcmp(ifname, word)==0) {
			found = 1;
		}
		if(found) break;
		unit ++;
	}

	if(!found) unit = WAN_UNIT_FIRST;
	return unit;
}
#else
int get_wan_unit(char *ifname)
{
	char tmp[100], prefix[32]="wanXXXXXX_";
	int unit = 0;
	int model = get_model();

	if(ifname == NULL)
		return -1;

	for(unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; ++unit){
		snprintf(prefix, sizeof(prefix), "wan%d_", unit);

		if(!strncmp(ifname, "ppp", 3) ){

			if(nvram_match(strcat_r(prefix, "pppoe_ifname", tmp), ifname)) {
				if (model ==  MODEL_RTN65U) {
					if(!nvram_match(strcat_r(prefix, "proto", tmp), "pppoe") || nvram_match(strcat_r(prefix, "is_usb_modem_ready", tmp), "1"))						
						return unit;
				}	
				else if (nvram_match(strcat_r(prefix, "state_t", tmp), "2") && nvram_match(strcat_r(prefix, "auxstate_t", tmp), "0") && nvram_match(strcat_r(prefix, "gw_ifname", tmp), ifname)) 
					return unit;				
			}

				
		}
		else if(nvram_match(strcat_r(prefix, "ifname", tmp), ifname)) {
			
			if (model == MODEL_RTN65U && !nvram_match(strcat_r(prefix, "proto", tmp), "l2tp") && !nvram_match(strcat_r(prefix, "proto", tmp), "pptp"))
					return unit;
			
			if (!nvram_match(strcat_r(prefix, "proto", tmp), "pppoe") && !nvram_match(strcat_r(prefix, "proto", tmp), "l2tp") && !nvram_match(strcat_r(prefix, "proto", tmp), "pptp") && nvram_match(strcat_r(prefix, "gw_ifname", tmp), ifname))
					return unit;						
		}   
	}

	return -1;
}
#endif

// Get physical wan ifname of working connection
char *get_wanx_ifname(int unit)
{
	char *wan_ifname;
	char tmp[100], prefix[sizeof("wanXXXXXXXXXX_")];
	
	snprintf(prefix, sizeof(prefix), "wan%d_", unit);
	wan_ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	return wan_ifname;
}

// Get wan ifname of working connection
char *get_wan_ifname(int unit)
{
	char *wan_proto, *wan_ifname;
	char tmp[100], prefix[sizeof("wanXXXXXXXXXX_")];

	snprintf(prefix, sizeof(prefix), "wan%d_", unit);
	wan_proto = nvram_safe_get(strcat_r(prefix, "proto", tmp));

#ifdef RTCONFIG_USB_MODEM
	if (dualwan_unit__usbif(unit)) {
		if (strcmp(wan_proto, "dhcp") == 0)
			wan_ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
		else
			wan_ifname = nvram_safe_get(strcat_r(prefix, "pppoe_ifname", tmp));
	} else
#endif
	if (strcmp(wan_proto, "pppoe") == 0 ||
	    strcmp(wan_proto, "pptp") == 0 ||
	    strcmp(wan_proto, "l2tp") == 0) {
		wan_ifname = nvram_safe_get(strcat_r(prefix, "pppoe_ifname", tmp));
	} else
		wan_ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

	return wan_ifname;
}

// Get wan ipv6 ifname of working connection
#ifdef RTCONFIG_IPV6
char *get_wan6_ifname(int unit)
{
	char *wan_proto, *wan_ifname;
	char tmp[100], prefix[sizeof("wanXXXXXXXXXX_")];

	switch (get_ipv6_service_by_unit(unit)) {
	case IPV6_NATIVE_DHCP:
	case IPV6_MANUAL:
#ifdef RTCONFIG_6RELAYD
	case IPV6_PASSTHROUGH:
#endif
		snprintf(prefix, sizeof(prefix), "wan%d_", unit);
		wan_proto = nvram_safe_get(strcat_r(prefix, "proto", tmp));

#ifdef RTCONFIG_USB_MODEM
		if (dualwan_unit__usbif(unit)) {
			if (strcmp(wan_proto, "dhcp") == 0)
				wan_ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
			else
				wan_ifname = nvram_safe_get(strcat_r(prefix, "pppoe_ifname", tmp));
		} else
#endif
		if (strcmp(wan_proto, "dhcp") != 0 && strcmp(wan_proto, "static") != 0 &&
		    nvram_match(ipv6_nvname_by_unit("ipv6_ifdev", unit), "ppp")) {
			wan_ifname = nvram_safe_get(strcat_r(prefix, "pppoe_ifname", tmp));
		} else
			wan_ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));
		break;
	case IPV6_6TO4:
	case IPV6_6IN4:
	case IPV6_6RD:
		/* no ipv6 multiwan tunnel support so far */
		wan_ifname = "v6tun0";
		break;
	default:
		return "";
	}

	return wan_ifname;
}
#endif

// OR all lan port status
int get_lanports_status(void)
{
	return lanport_status();
}

extern int wanport_status(int wan_unit);

// OR all wan port status
int get_wanports_status(int wan_unit)
{
// 1. PHY type, 2. factory owner, 3. model.
#ifdef RTCONFIG_DSL
#ifdef RTCONFIG_DUALWAN
	if(get_dualwan_by_unit(wan_unit) == WANS_DUALWAN_IF_DSL)
#endif
	{
		if (nvram_match("dsltmp_adslsyncsts","up")) return 1;
		return 0;
	}
#ifdef RTCONFIG_DUALWAN
	if(get_dualwan_by_unit(wan_unit) == WANS_DUALWAN_IF_LAN)
	{
	#ifdef RTCONFIG_RALINK
		return rtkswitch_wanPort_phyStatus(wan_unit); //Paul modify 2012/12/4
	#else
		return wanport_status(wan_unit);
	#endif
	}
#endif
	// TO CHENI:
	// HOW TO HANDLE USB?	
#else // RJ-45
#if defined(RTCONFIG_RALINK) || defined(RTCONFIG_QCA)
	return rtkswitch_wanPort_phyStatus(wan_unit);
#else
	return wanport_status(wan_unit);
#endif
#endif
}

int get_usb_modem_state(){
	if(!strcmp(nvram_safe_get("modem_running"), "1"))
		return 1;
	else
		return 0;
}

int set_usb_modem_state(const int flag){
	if(flag != 1 && flag != 0)
		return 0;

	if(flag){
		nvram_set("modem_running", "1");
		return 1;
	}
	else{
		nvram_set("modem_running", "0");
		return 0;
	}
}

int
set_wan_primary_ifunit(const int unit)
{
	char tmp[100], prefix[] = "wanXXXXXXXXXX_";
	int i;

	if (unit < WAN_UNIT_FIRST || unit >= WAN_UNIT_MAX)
		return -1;

	nvram_set_int("wan_primary", unit);
	for (i = WAN_UNIT_FIRST; i < WAN_UNIT_MAX; i++) {
		snprintf(prefix, sizeof(prefix), "wan%d_", i);
		nvram_set_int(strcat_r(prefix, "primary", tmp), (i == unit) ? 1 : 0);
	}

	return 0;
}

int
wan_primary_ifunit(void)
{
	char tmp[100], prefix[] = "wanXXXXXXXXXX_";
	int unit;

	/* TODO: Why not just nvram_get_int("wan_primary")? */
	for (unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; unit ++) {
		snprintf(prefix, sizeof(prefix), "wan%d_", unit);
		if (nvram_match(strcat_r(prefix, "primary", tmp), "1"))
			return unit;
	}

	return 0;
}

int
wan_primary_ifunit_ipv6(void)
{
#ifdef RTCONFIG_DUALWAN
#if defined(RTCONFIG_MULTIWAN_CFG)
	int unit = wan_primary_ifunit();

	if (!strstr(nvram_safe_get("wans_dualwan"), "none")
	    && !strcmp(nvram_safe_get("wans_mode"), "lb")
#ifdef RTCONFIG_IPV6
	    && get_ipv6_service_by_unit(unit) == IPV6_DISABLED
#endif
	)
		return (1 - unit);

	return unit;
#else
	return 0;
#endif
#else
	return wan_primary_ifunit();
#endif
}

#ifdef RTCONFIG_MEDIA_SERVER
void
set_invoke_later(int flag)
{
	nvram_set_int("invoke_later", nvram_get_int("invoke_later")|flag);
}

int
get_invoke_later()
{
	return(nvram_get_int("invoke_later"));
}
#endif	/* RTCONFIG_MEDIA_SERVER */

#ifdef RTCONFIG_USB

char xhci_string[32];
char ehci_string[32];
char ohci_string[32];

char *get_usb_xhci_port(int port)
{
        char word[100], *next;
        int i=0;

        strcpy(xhci_string, "xxxxxxxx");

        foreach(word, nvram_safe_get("xhci_ports"), next) {
                if(i==port) {
                        strcpy(xhci_string, word);
                        break;
                }
                i++;
        }
        return xhci_string;
}

char *get_usb_ehci_port(int port)
{
	char word[100], *next;
	int i=0;

	strcpy(ehci_string, "xxxxxxxx");

	foreach(word, nvram_safe_get("ehci_ports"), next) {
		if(i==port) {
			strcpy(ehci_string, word);
			break;
		}		
		i++;
	}
	return ehci_string;
}

char *get_usb_ohci_port(int port)
{
	char word[100], *next;
	int i=0;

	strcpy(ohci_string, "xxxxxxxx");

	foreach(word, nvram_safe_get("ohci_ports"), next) {
		if(i==port) {
			strcpy(ohci_string, word);
			break;
		}		
		i++;
	}
	return ohci_string;
}

int get_usb_port_number(const char *usb_port)
{
	char word[100], *next;
	int port_num, i;

	port_num = 0;
	i = 0;
	foreach(word, nvram_safe_get("xhci_ports"), next){
		++i;
		if(!strcmp(usb_port, word)){
			port_num = i;
			break;
		}
	}

	i = 0;
	if(port_num == 0){
		foreach(word, nvram_safe_get("ehci_ports"), next){
			++i;
			if(!strcmp(usb_port, word)){
				port_num = i;
				break;
			}
		}
	}

	i = 0;
	if(port_num == 0){
		foreach(word, nvram_safe_get("ohci_ports"), next){
			++i;
			if(!strcmp(usb_port, word)){
				port_num = i;
				break;
			}
		}
	}

	return port_num;
}

int get_usb_port_host(const char *usb_port)
{
	char word[100], *next;
	int i;

	i = 0;
	foreach(word, nvram_safe_get("xhci_ports"), next){
		++i;
		if(!strcmp(usb_port, word)){
			return USB_HOST_XHCI;
		}
	}

	i = 0;
	foreach(word, nvram_safe_get("ehci_ports"), next){
		++i;
		if(!strcmp(usb_port, word)){
			return USB_HOST_EHCI;
		}
	}

	i = 0;
	foreach(word, nvram_safe_get("ohci_ports"), next){
		++i;
		if(!strcmp(usb_port, word)){
			return USB_HOST_OHCI;
		}
	}

	return USB_HOST_NONE;
}
#endif

#ifdef RTCONFIG_DUALWAN
void set_wanscap_support(char *feature)
{
	nvram_set("wans_cap", feature);
}

void add_wanscap_support(char *feature)
{
	char features[128];

	strcpy(features, nvram_safe_get("wans_cap"));

	if(strlen(features)==0) nvram_set("wans_cap", feature);
	else {
		sprintf(features, "%s %s", features, feature);
		nvram_set("wans_cap", features);
	}
}

int get_wans_dualwan(void) 
{
	int caps=0;
	char word[80], *next;
	char *wancaps = nvram_get("wans_dualwan");

	if(wancaps == NULL)
	{
#ifdef RTCONFIG_DSL
		caps =  WANSCAP_DSL;
#else
		caps = WANSCAP_WAN;
#endif
		wancaps = DEF_SECOND_WANIF;
	}

	foreach(word, wancaps, next) {
		if (!strcmp(word,"lan")) caps |= WANSCAP_LAN;
		if (!strcmp(word,"2g")) caps |= WANSCAP_2G;
		if (!strcmp(word,"5g")) caps |= WANSCAP_5G;
		if (!strcmp(word,"usb")) caps |= WANSCAP_USB;
		if (!strcmp(word,"dsl")) caps |= WANSCAP_DSL;
		if (!strcmp(word,"wan")) caps |= WANSCAP_WAN;
		if (!strcmp(word,"wan2")) caps |= WANSCAP_WAN2;
	}

	return caps;
}

int get_dualwan_by_unit(int unit) 
{
	int i;
	char word[80], *next;
	char *wans_dualwan = nvram_get("wans_dualwan");

	if(wans_dualwan == NULL)	//default value
	{
		wans_dualwan = nvram_default_get("wans_dualwan");
	}

#ifdef RTCONFIG_MULTICAST_IPTV
	if(unit == WAN_UNIT_IPTV)
		return WAN_UNIT_IPTV;
        if(unit == WAN_UNIT_VOIP)
                return WAN_UNIT_VOIP;
#endif

	i = 0;
	foreach(word, wans_dualwan, next) {
		if(i==unit) {
			if (!strcmp(word,"lan")) return WANS_DUALWAN_IF_LAN;
			if (!strcmp(word,"2g")) return WANS_DUALWAN_IF_2G;
			if (!strcmp(word,"5g")) return WANS_DUALWAN_IF_5G;
			if (!strcmp(word,"usb")) return WANS_DUALWAN_IF_USB;	
			if (!strcmp(word,"dsl")) return WANS_DUALWAN_IF_DSL;
			if (!strcmp(word,"wan")) return WANS_DUALWAN_IF_WAN;
			if (!strcmp(word,"wan2")) return WANS_DUALWAN_IF_WAN2;
#ifdef RTCONFIG_USB_MULTIMODEM
			if (!strcmp(word,"usb2")) return WANS_DUALWAN_IF_USB2;
#endif
			return WANS_DUALWAN_IF_NONE;
		}
		i++;
	}

	return WANS_DUALWAN_IF_NONE;
}

int get_wanunit_by_type(int wan_type){
	int unit;

	for(unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; ++unit){
		if(get_dualwan_by_unit(unit) == wan_type){
			return unit;
		}
	}

	return WAN_UNIT_NONE;
}

// imply: unit 0: primary, unit 1: secondary
int get_dualwan_primary(void)
{
	return get_dualwan_by_unit(0);
}

int get_dualwan_secondary(void) 
{
	return get_dualwan_by_unit(1);
}

/**
 * Return total number of WAN unit.
 * @return:
 */
int get_nr_wan_unit(void)
{
	int i, c = 0;

	for (i = WAN_UNIT_FIRST; i < WAN_UNIT_MAX; ++i) {
		if (get_dualwan_by_unit(i) != WANS_DUALWAN_IF_NONE)
			c++;
	}

	return c;
}
#endif	/* RTCONFIG_DUALWAN */

/**
 * Return number of enabled guest network of one/all band.
 * @band:
 *  >= 0:	calculate number of enabled guest network of specified band.
 *  <  0:	calculate number of enabled guest network of all band.
 * @return:	number of enabled guest network of one/all band.
 */
int get_nr_guest_network(int band)
{
	int i, j, c = 0, mode = get_model();
	char prefix[16];

	if (__repeater_mode(mode) || __mediabridge_mode(mode))
		return 0;

	/* 0:	2G
	 * 1:	5G
	 * 2:	5G-2, may not exist.
	 * 3:	Wigig=11ad, may not exist.
	 */
	for (i = 0; i < 4; ++i) {
		if (band >= 0 && band != i)
			continue;

		for (j = 1; j < MAX_NO_MSSID; ++j) {
			snprintf(prefix, sizeof(prefix), "wl%d.%d_", i, j);
			if (nvram_pf_match(prefix, "bss_enabled", "1"))
				c++;
		}
	}

	return c;
}

int get_gate_num(void)
{
	char prefix[] = "wanXXXXXXXXXX_", link_wan[sizeof("link_wanXXXXXX")];
	char wan_ip[32], wan_gate[32];
	int unit;
	int gate_num = 0;
	for (unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; ++unit){ // Multipath
		snprintf(prefix, sizeof(prefix), "wan%d_", unit);
		strncpy(wan_ip, nvram_pf_safe_get(prefix, "ipaddr"), 32);
		strncpy(wan_gate, nvram_pf_safe_get(prefix, "gateway"), 32);

		// when wan_down().
		if(!is_wan_connect(unit))
			continue;

		/* We need to check link_wanX instead of wanX_state_t if this WAN unit is static IP. */
		if (nvram_pf_match(prefix, "proto", "static") && dualwan_unit__nonusbif(unit)) {
			if (unit == WAN_UNIT_FIRST)
				strlcpy(link_wan, "link_wan", sizeof(link_wan));
			else
				snprintf(link_wan, sizeof(link_wan), "link_wan%d", unit);

			if (!nvram_match(link_wan, "1"))
				continue;
		}

		if(strlen(wan_gate) <= 0 || !strcmp(wan_gate, "0.0.0.0"))
			continue;

		if(strlen(wan_ip) <= 0 || !strcmp(wan_ip, "0.0.0.0"))
			continue;

		++gate_num;
#ifndef	RTCONFIG_DUALWAN
		break;
#endif	/* RTCONFIG_DUALWAN */
	}
	return gate_num;
}

// no more to use
/*
void set_dualwan_type(char *type)
{
	nvram_set("wans_dualwan", type);
}

void add_dualwan_type(char *type)
{
	char types[128];

	strcpy(types, nvram_safe_get("wans_dualwan"));

	if(strlen(types)==0) nvram_set("wans_dualwan", type);
	else {
		sprintf(types, "%s %s", types, type);
		nvram_set("wans_dualwan", types);
	}
}
*/

void set_lan_phy(char *phy)
{
	nvram_set("lan_ifnames", phy);
}

void add_lan_phy(char *phy)
{
	char phys[128];

	strcpy(phys, nvram_safe_get("lan_ifnames"));

	if(strlen(phys)==0) nvram_set("lan_ifnames", phy);
	else {
		sprintf(phys, "%s %s", phys, phy);
		nvram_set("lan_ifnames", phys);
	}
}

void set_wan_phy(char *phy)
{
	nvram_set("wan_ifnames", phy);
}

void add_wan_phy(char *phy)
{
	char phys[128];

	strcpy(phys, nvram_safe_get("wan_ifnames"));

	if(strlen(phys)==0) nvram_set("wan_ifnames", phy);
	else {
		sprintf(phys, "%s %s", phys, phy);
		nvram_set("wan_ifnames", phys);
	}
}

char *usb_modem_prefix(int modem_unit, char *prefix, int size)
{
	if (prefix == NULL)
		return NULL;

	if (modem_unit == MODEM_UNIT_FIRST)
		snprintf(prefix, size, "usb_modem_");
	else
		snprintf(prefix, size, "usb_modem%d_", modem_unit);

	return prefix;
}

#ifdef RTCONFIG_USB_MULTIMODEM
int get_modemunit_by_dev(const char *dev){
	int modem_unit;
	char tmp[100], prefix[32];

	for(modem_unit = MODEM_UNIT_FIRST; modem_unit < MODEM_UNIT_MAX; ++modem_unit){
		usb_modem_prefix(modem_unit, prefix, sizeof(prefix));

		if(!strcmp(dev, nvram_safe_get(strcat_r(prefix, "act_dev", tmp))))
			return modem_unit;
	}

	return MODEM_UNIT_NONE;
}

int get_modemunit_by_node(const char *usb_node){
	int modem_unit;
	char tmp[100], prefix[32];

	for(modem_unit = MODEM_UNIT_FIRST; modem_unit < MODEM_UNIT_MAX; ++modem_unit){
		usb_modem_prefix(modem_unit, prefix, sizeof(prefix));

		if(!strcmp(usb_node, nvram_safe_get(strcat_r(prefix, "act_path", tmp))))
			return modem_unit;
	}

	return MODEM_UNIT_NONE;
}
#else
inline int get_modemunit_by_dev(const char *dev){
	return MODEM_UNIT_FIRST;
}
inline int get_modemunit_by_node(const char *usb_node){
	return MODEM_UNIT_FIRST;
}
#endif

int get_modemunit_by_type(int wan_type){
	// Simple way
#ifdef RTCONFIG_USB_MULTIMODEM
	if(wan_type == WANS_DUALWAN_IF_USB2)
		return MODEM_UNIT_SECOND;
	else
#endif
	if(wan_type == WANS_DUALWAN_IF_USB)
		return MODEM_UNIT_FIRST;
	else
		return MODEM_UNIT_NONE;
}

int get_wantype_by_modemunit(int modem_unit){
	// Simple way
#ifdef RTCONFIG_USB_MULTIMODEM
	if(modem_unit == MODEM_UNIT_SECOND)
		return WANS_DUALWAN_IF_USB2;
	else
#endif
	if(modem_unit == MODEM_UNIT_FIRST)
		return WANS_DUALWAN_IF_USB;
	else
		return WANS_DUALWAN_IF_NONE;
}

#if defined(RTCONFIG_CONCURRENTREPEATER)
char ssid[64]={0};
char *get_default_ssid(int unit, int band_num)
{
	char *result = NULL;
	int i=0;
	unsigned char ssidbase[16];

	char *macp = NULL;
	unsigned char mac_binary[6];

	memset(ssid, 0x0, sizeof(ssid));

#if defined(RTCONFIG_NEWSSID_REV2)

	macp = get_2g_hwaddr();
	ether_atoe(macp, mac_binary);
	sprintf((char *)ssidbase, "ASUS_%02X", mac_binary[5]);
#else
	macp = get_lan_hwaddr();
	ether_atoe(macp, mac_binary);
	sprintf((char *)ssidbase, "%s_%02X", get_productid(), mac_binary[5]);
#endif	


#if defined(RTCONFIG_NEWSSID_REV2)
			sprintf((char *)ssid, "%s%s", ssidbase, unit ? (unit == 2 ? "_5G-2" : (band_num > 2 ? "_5G-1" : "_5G")) : (band_num > 1 ? "_2G" : ""));
#else
			sprintf((char *)ssid, "%s%s", ssidbase, unit ? (unit == 2 ? "_5G-2" : "_5G") : "_2G");
#endif

	fprintf(stderr,"###### Default ssid = %s\n", ssid);
	return ssid;
}
#endif

