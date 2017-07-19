/*
	connections.c to record wireless device in networkmap
*/
#include <bcmnvram.h>
#include "networkmap.h"
#include <stdio.h>
#include <shutils.h>

#ifdef RTCONFIG_RALINK
#include <ralink.h>
#include <iwlib.h>
#else
#ifdef RTCONFIG_QCA
#include <qca.h>
#include <iwlib.h>
#else
#include <wlioctl.h>
#endif
#endif

#ifdef RTCONFIG_QTN
#include "web-qtn.h"
#endif


/* define */
#define _DEBUG_			"/tmp/conn_debug"
#define _CONNLOG_		"[connection log]"
#ifndef RTCONFIG_RALINK
#define CONN_DEBUG(fmt, args...) \
	if(f_exists(_DEBUG_)) { \
		cprintf(fmt, ## args); \
	}
#else
#define CONN_DEBUG(fmt, args...) \
	if(f_exists(_DEBUG_)) { \
		printf(fmt, ## args); \
	}
#endif
#define ETHER_ADDR_STR_LEN	18
#define	MAX_STA_COUNT		128

#ifdef RTCONFIG_QTN
#define	WIFINAME		"wifi0"
#endif

/* The below macros handle endian mis-matches between wl utility and wl driver. */
static bool g_swap = FALSE;
#define htod32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh32(i) (g_swap?bcmswap32(i):(uint32)(i))
#define dtoh16(i) (g_swap?bcmswap16(i):(uint16)(i))
#define dtohchanspec(i) (g_swap?dtoh16(i):i)

/* struct */
typedef struct log_info log_s;
struct log_info{
	unsigned char	mac[6];
	unsigned char	wireless;
	char txrate[7];
	char rxrate[10];
	int  rssi;
	char conn_time[12];
#if defined(BRTAC828)
	char subunit;
#endif
	log_s *next;
};

/* debug */
static int debug = 0;

/* global */
static log_s *head = NULL;
static log_s *prev = NULL;


#if !defined(RTCONFIG_RALINK) && !defined(RTCONFIG_QCA) && !defined(RTCONFIG_REALTEK)
sta_info_t *
wl_sta_info(char *ifname, struct ether_addr *ea)
{
	static char buf[sizeof(sta_info_t)];
	sta_info_t *sta = NULL;

	strcpy(buf, "sta_info");
	memcpy(buf + strlen(buf) + 1, (void *)ea, ETHER_ADDR_LEN);

	if (!wl_ioctl(ifname, WLC_GET_VAR, buf, sizeof(buf))) {
		sta = (sta_info_t *)buf;
		sta->ver = dtoh16(sta->ver);

		/* Report unrecognized version */
		if (sta->ver > WL_STA_VER) {
			dbg(" ERROR: unknown driver station info version %d\n", sta->ver);
			return NULL;
		}

		sta->len = dtoh16(sta->len);
		sta->cap = dtoh16(sta->cap);
#ifdef RTCONFIG_BCMARM
		sta->aid = dtoh16(sta->aid);
#endif
		sta->flags = dtoh32(sta->flags);
		sta->idle = dtoh32(sta->idle);
		sta->rateset.count = dtoh32(sta->rateset.count);
		sta->in = dtoh32(sta->in);
		sta->listen_interval_inms = dtoh32(sta->listen_interval_inms);
#ifdef RTCONFIG_BCMARM
		sta->ht_capabilities = dtoh16(sta->ht_capabilities);
		sta->vht_flags = dtoh16(sta->vht_flags);
#endif
	}

	return sta;
}
#endif

#ifdef RTCONFIG_RALINK
static void MTK_stainfo(int unit)
{
	char tmp[128], prefix[] = "wlXXXXXXXXXX_", *ifname;
	char data[16384];
	struct iwreq wrq3;
	int rssi, cnt;

	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	ifname = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

#if defined(RTAC85U)
	if (!nvram_get_int("wlready"))
		return;
#endif
	memset(data, 0, sizeof(data));
	wrq3.u.data.pointer = data;
	wrq3.u.data.length = sizeof(data);
	wrq3.u.data.flags = 0;

	if ((wl_ioctl(ifname, RTPRIV_IOCTL_GET_MAC_TABLE, &wrq3)) < 0) {
		return;
	}

	RT_802_11_MAC_TABLE_5G* mp =(RT_802_11_MAC_TABLE_5G*)wrq3.u.data.pointer;
	RT_802_11_MAC_TABLE_2G* mp2=(RT_802_11_MAC_TABLE_2G*)wrq3.u.data.pointer;
	int i;

	if (!strcmp(ifname, WIF_2G)) {
		for ( i=0; i < mp2->Num; i++) {
			RT_802_11_MAC_ENTRY_for_2G *Entry = ((RT_802_11_MAC_ENTRY_for_2G *)(mp2->Entry)) + i;

			/* linked list */
			log_s *current;
			current = (struct log_info *)malloc(sizeof(struct log_info));
			/* initial */
			memset(current, 0x00, sizeof(struct log_info));

			// mac
			strncpy(current->mac, Entry->Addr, 6);
			current->wireless = 1;

			//rssi
			rssi = cnt = 0;
			if (mp2->Entry[i].AvgRssi0) {
				rssi += mp2->Entry[i].AvgRssi0;
				cnt++;
			}
			if (mp2->Entry[i].AvgRssi1) {
				rssi += mp2->Entry[i].AvgRssi1;
				cnt++;
			}
			if (mp2->Entry[i].AvgRssi2) {
				rssi += mp2->Entry[i].AvgRssi2;
				cnt++;
			}
			rssi = rssi / cnt;
			current->rssi = rssi;

			if(debug) CONN_DEBUG("%s[%3d,MTK] %02X%02X%02X%02X%02X%02X, rssi: %d\n", 
						_CONNLOG_, i, current->mac[0], current->mac[1], current->mac[2], 
						current->mac[3], current->mac[4], current->mac[5], current->rssi);

			current->next = NULL;
			if(head == NULL)
				head = current;
			else
				prev->next = current;

			prev = current;
		}
	}
	else {
		for (i=0;i<mp->Num;i++) {
			RT_802_11_MAC_ENTRY_for_5G *Entry = ((RT_802_11_MAC_ENTRY_for_5G *)(mp->Entry)) + i;

			/* linked list */
			log_s *current;
			current = (struct log_info *)malloc(sizeof(struct log_info));
			/* initial */
			memset(current, 0x00, sizeof(struct log_info));

			// mac
			strncpy(current->mac, Entry->Addr, 6);
			current->wireless = 2;

			//rssi
			rssi = cnt = 0;
			if (mp->Entry[i].AvgRssi0) {
				rssi += mp->Entry[i].AvgRssi0;
				cnt++;
			}
			if (mp->Entry[i].AvgRssi1) {
				rssi += mp->Entry[i].AvgRssi1;
				cnt++;
			}
			if (mp->Entry[i].AvgRssi2) {
				rssi += mp->Entry[i].AvgRssi2;
				cnt++;
			}
			rssi = rssi / cnt;
			current->rssi = rssi;

			if(debug) CONN_DEBUG("%s[%3d,MTK] %02X%02X%02X%02X%02X%02X rssi: %d\n", 
						_CONNLOG_, i, current->mac[0], current->mac[1], current->mac[2], 
						current->mac[3], current->mac[4], current->mac[5], current->rssi);


			current->next = NULL;
			if(head == NULL)
				head = current;
			else
				prev->next = current;

			prev = current;
		}
	}

}

static void get_MTK_stainfo()
{
	int ii = 0;
	char word[256], *next;

	if(debug) CONN_DEBUG("MTK stainfo start\n");
	foreach (word, nvram_safe_get("wl_ifnames"), next)
	{
		MTK_stainfo(ii);
		ii++;
	}
}
#else
#ifdef RTCONFIG_QCA
#define STA_INFO_PATH "/tmp/wl_list"
int hctoi(const char h){
    if(isdigit(h))
        return h - '0';
    else
        return toupper(h) - 'A' + 10;
}

static int QCA_stainfo(const char *if_name, char id)
{
	if(debug) CONN_DEBUG("%s[QCA] scan interface %s\n", _CONNLOG_, if_name);
	FILE *fp;
	int i, ret = 0, l2_offset, subunit;
	char *ifname, *l2, *l3;
	char line_buf[300]; // max 14x
	char subunit_char = '0';
	char mac[18], num[2];
	unsigned char unit = 0;
	unsigned int dummy;

	ifname = strdup(if_name);
	num[0] = ifname[3];
	num[1] = '\0';
	unit = atoi(num);

	if (unit < 0 || unit >= MAX_NR_WL_IF)
		return -1;
	if (!ifname || *ifname == '\0')
		return -1;

	subunit = get_wlsubnet((int)unit, ifname);
	if (subunit < 0)
		subunit = 0;

	if (subunit >= 0 && subunit < MAX_NO_MSSID)
		subunit_char = '0' + subunit;
	if (id == 'B' || id == 'F' || id == 'C')
		subunit_char = id;

	doSystem("wlanconfig %s list > %s", ifname, STA_INFO_PATH);
	fp = fopen(STA_INFO_PATH, "r");
	if (fp) {
/* wlanconfig ath1 list
ADDR               AID CHAN TXRATE RXRATE RSSI IDLE  TXSEQ  RXSEQ  CAPS        ACAPS     ERP    STATE MAXRATE(DOT11) HTCAPS ASSOCTIME    IEs   MODE PSMODE
00:10:18:55:cc:08    1  149  55M   1299M   63    0      0   65535               0        807              0              Q 00:10:33 IEEE80211_MODE_11A  0
08:60:6e:8f:1e:e6    2  149 159M    866M   44    0      0   65535     E         0          b              0           WPSM 00:13:32 WME IEEE80211_MODE_11AC_VHT80  0
08:60:6e:8f:1e:e8    1  157 526M    526M   51 4320      0   65535    EP         0          b              0          AWPSM 00:00:10 RSN WME IEEE80211_MODE_11AC_VHT80 0
*/
		//fseek(fp, 131, SEEK_SET);	// ignore header
		fgets(line_buf, sizeof(line_buf), fp); // ignore header
		l2 = strstr(line_buf, "ACAPS");
		if (l2 != NULL)
			l2_offset = (int)(l2 - line_buf);
		else {
			l2_offset = 79;
			l2 = line_buf + l2_offset;
		}
		while ( fgets(line_buf, sizeof(line_buf), fp) ) {
			/* IEs may be empty string, find IEEE80211_MODE_ before parsing mode and psmode. */
			l3 = strstr(line_buf, "IEEE80211_MODE_");
			if (l3) {
				*(l3 - 1) = '\0';
			}
			*(l2 - 1) = '\0';
			/* linked list */
			log_s *current;
			current = (struct log_info *)malloc(sizeof(struct log_info));
			/* initial */
			memset(current, 0x00, sizeof(struct log_info));
#if defined(BRTAC828)
			current->subunit = subunit_char;
#endif
			sscanf(line_buf, "%s%u%u%s%s%u",
				mac, &dummy, &dummy, current->txrate, current->rxrate, &current->rssi);
			sscanf(l2, "%u%x%u%s%s",
				&dummy, &dummy, &dummy, &dummy, current->conn_time);
			if (strlen(current->rxrate) >= 6)
				strcpy(current->rxrate, "0M");
			for(i = 0; i < 6; i++) {
				current->mac[i] = hctoi(mac[i*3])*16 + hctoi(mac[i*3+1]);
			}
			current->wireless = unit + 1;

#if defined(BRTAC828)
			if(debug) CONN_DEBUG("%s[QCA] %02X%02X%02X%02X%02X%02X %s wl:%d %d, rx %s tx %s rssi %d conn_time %s subunit %c\n", 
						_CONNLOG_, current->mac[0], current->mac[1], current->mac[2], 
						current->mac[3], current->mac[4], current->mac[5], ifname, current->wireless, unit,
						current->rxrate, current->txrate, current->rssi, current->conn_time, current->subunit);
#else
			if(debug) CONN_DEBUG("%s[QCA] %02X%02X%02X%02X%02X%02X %s wl:%d %d, rx %s tx %s rssi %d conn_time %s\n", 
						_CONNLOG_, current->mac[0], current->mac[1], current->mac[2], 
						current->mac[3], current->mac[4], current->mac[5], ifname, current->wireless, unit,
						current->rxrate, current->txrate, current->rssi, current->conn_time);
#endif

			current->next = NULL;
			if(head == NULL)
				head = current;
			else
				prev->next = current;

			prev = current;
		}

		fclose(fp);
		unlink(STA_INFO_PATH);
	}
	free(ifname);

	return ret;
}
static void get_QCA_stainfo()
{
	int ii = 0;
	char word[256], *next;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_", fbifname1[32], fbifname2[32];

	if(debug) CONN_DEBUG("QCA stainfo start\n");
	foreach (word, nvram_safe_get("wl_ifnames"), next)
	{
		QCA_stainfo(word, 0);
	}
#ifdef RTCONFIG_CAPTIVE_PORTAL
	/* Free Wi-Fi */
	if(nvram_match("captive_portal_enable", "on")) {
		foreach (word, nvram_safe_get("lan1_ifnames"), next)
		{
			QCA_stainfo(word, 'F');
		}
	}
	/* Captive Portal */
	if(nvram_match("captive_portal_adv_enable", "on")) {
		foreach (word, nvram_safe_get("lan2_ifnames"), next)
		{
			QCA_stainfo(word, 'C');
		}
	}
#endif
#if defined(RTCONFIG_FBWIFI)
	/* Facebook Wi-Fi */
	if(nvram_match("fbwifi_enable", "on")) {
		if(!nvram_match("fbwifi_2g", "off")) {
 			snprintf(prefix, sizeof(prefix), nvram_safe_get("fbwifi_2g"));
			strncpy(fbifname1, nvram_safe_get(strcat_r(prefix, "_ifname", tmp)), 32);
			if(debug) CONN_DEBUG("[QCA] fb wifi ifname 2g %s\n", fbifname1);
			QCA_stainfo(fbifname1, 'B');
		}
		if(!nvram_match("fbwifi_5g", "off")) {
 			snprintf(prefix, sizeof(prefix), nvram_safe_get("fbwifi_5g"));
			strncpy(fbifname2, nvram_safe_get(strcat_r(prefix, "_ifname", tmp)), 32);
			if(debug) CONN_DEBUG("[QCA] fb wifi ifname 5g %s\n", fbifname2);
			QCA_stainfo(fbifname2, 'B');
		}
	}
#endif
	foreach (word, nvram_safe_get("lan_ifnames"), next)
	{
		if(debug) CONN_DEBUG("[QCA] rest if scan %s\n", word);
		if(strstr(nvram_safe_get("wl_ifnames"), word))
			continue;
#ifdef RTCONFIG_CAPTIVE_PORTAL
		if(nvram_match("captive_portal_enable", "on")) {
			if(nvram_safe_get("lan1_ifnames")) {
				if(strstr(nvram_safe_get("lan1_ifnames"), word))
					continue;
			}
		}
		if(nvram_match("captive_portal_adv_enable", "on")) {
			if(nvram_safe_get("lan2_ifnames")) {
				if(strstr(nvram_safe_get("lan2_ifnames"), word))
					continue;
			}
		}
#endif
#if defined(RTCONFIG_FBWIFI)
		if(fbifname1) {
			if(!strcmp(word, fbifname1))
				continue;
		}
		if(fbifname2) {
			if(!strcmp(word, fbifname2))
				continue;
		}
#endif
		if(strstr(word, "ath"))
			QCA_stainfo(word, 1);
	}
}
#else
char *
print_rate_buf_compact(int raw_rate, char *buf)
{
	if (!buf) return NULL;

	if (raw_rate == -1)
		sprintf(buf, "        ");
	else if ((raw_rate % 1000) == 0)
		sprintf(buf, "%d", raw_rate / 1000);
	else
		sprintf(buf, "%.1f", (double) raw_rate / 1000);

	return buf;
}

static void BRCM_stainfo(int unit)
{
	/* initial */
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";
	char *name;
	struct maclist *auth = NULL;
	int mac_list_size;
	char ea[ETHER_ADDR_STR_LEN];
	scb_val_t scb_val;
	char name_vif[] = "wlX.Y_XXXXXXXXXX";
	int i, ii;
	sta_info_t *sta;
	char rate_buf[8];
	int hr, min, sec;

	/* get wireless stainfo */
	snprintf(prefix, sizeof(prefix), "wl%d_", unit);
	name = nvram_safe_get(strcat_r(prefix, "ifname", tmp));

#ifdef RTCONFIG_WIRELESSREPEATER
	if ((nvram_get_int("sw_mode") == SW_MODE_REPEATER)
		&& (nvram_get_int("wlc_band") == unit))
	{
		sprintf(name_vif, "wl%d.%d", unit, 1);
		name = name_vif;
	}
#endif

	if (!strlen(name))
		goto exit;

	/* buffers and length */
	mac_list_size = sizeof(auth->count) + MAX_STA_COUNT * sizeof(struct ether_addr);
	auth = malloc(mac_list_size);

	if (!auth)
		goto exit;

	memset(auth, 0, mac_list_size);

	/* query wl for authenticated sta list */
	strcpy((char*)auth, "authe_sta_list");
	if (wl_ioctl(name, WLC_GET_VAR, auth, mac_list_size))
		goto exit;

	/* build authenticated sta list */
	for(i = 0; i < auth->count; ++i) {
#ifndef RTCONFIG_REALTEK
		sta = wl_sta_info(name, &auth->ea[i]);
		if (!sta) continue;
		if (!(sta->flags & WL_STA_ASSOC) && !sta->in) continue;
#endif

		/* linked list */
		log_s *current;
		current = (struct log_info *)malloc(sizeof(struct log_info));
		/* initial */
		memset(current, 0x00, sizeof(struct log_info));

		// mac
		strncpy(current->mac, &auth->ea[i], 6);
		current->wireless = unit + 1;
		memcpy(&scb_val.ea, &auth->ea[i], ETHER_ADDR_LEN);
		if (wl_ioctl(name, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t))) {
			current->rssi = 0;
		} else {
			current->rssi = scb_val.val;
		}
#ifdef RTCONFIG_STAINFO
		/* wireless log */
		strlcpy(current->txrate, print_rate_buf_compact(sta->tx_rate, rate_buf), sizeof(current->txrate));
		strlcpy(current->rxrate, print_rate_buf_compact(sta->rx_rate, rate_buf), sizeof(current->rxrate));
		hr = sta->in / 3600;
		min = (sta->in % 3600) / 60;
		sec = sta->in - hr * 3600 - min * 60;
		sprintf(current->conn_time, "%02d:%02d:%02d", hr, min, sec);

		if(debug) CONN_DEBUG("%s[%3d,BRCM] %02X%02X%02X%02X%02X%02X wl:%d %d, rx %s tx %s rssi %d conn_time %s\n", 
					_CONNLOG_, i, current->mac[0], current->mac[1], current->mac[2], 
					current->mac[3], current->mac[4], current->mac[5], current->wireless, unit,
					current->rxrate, current->txrate, current->rssi, current->conn_time);
#else
		if(debug) CONN_DEBUG("%s[%3d,BRCM] %02X%02X%02X%02X%02X%02X\n", 
					_CONNLOG_, i, current->mac[0], current->mac[1], current->mac[2], 
					current->mac[3], current->mac[4], current->mac[5]);
#endif

		current->next = NULL;
		if(head == NULL)
			head = current;
		else
			prev->next = current;

		prev = current;
	}

	for (i = 1; i < 4; i++) {
#ifdef RTCONFIG_WIRELESSREPEATER
		if ((nvram_get_int("sw_mode") == SW_MODE_REPEATER)
			&& (unit == nvram_get_int("wlc_band")) && (i == 1))
			break;
#endif
		sprintf(prefix, "wl%d.%d_", unit, i);
		if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1"))
		{
			sprintf(name_vif, "wl%d.%d", unit, i);

			memset(auth, 0, mac_list_size);

			/* query wl for authenticated sta list */
			strcpy((char*)auth, "authe_sta_list");
			if (wl_ioctl(name_vif, WLC_GET_VAR, auth, mac_list_size))
				goto exit;

			for(ii = 0; ii < auth->count; ii++) {
#ifndef RTCONFIG_REALTEK
				sta = wl_sta_info(name_vif, &auth->ea[ii]);
				if (!sta) continue;
#endif

				/* linked list */
				log_s *current;
				current = (struct log_info *)malloc(sizeof(struct log_info));
				/* initial */
				memset(current, 0x00, sizeof(struct log_info));

				// mac
				strncpy(current->mac, &auth->ea[ii], 6);
				current->wireless = unit + 1;


				memcpy(&scb_val.ea, &auth->ea[ii], ETHER_ADDR_LEN);
				if (wl_ioctl(name_vif, WLC_GET_RSSI, &scb_val, sizeof(scb_val_t))) {
					current->rssi = 0;
				} else {
					current->rssi = scb_val.val;
				}
#ifdef RTCONFIG_STAINFO
				/* wireless log */
				strlcpy(current->txrate, print_rate_buf_compact(sta->tx_rate, rate_buf), sizeof(current->txrate));
				strlcpy(current->rxrate, print_rate_buf_compact(sta->rx_rate, rate_buf), sizeof(current->rxrate));
				hr = sta->in / 3600;
				min = (sta->in % 3600) / 60;
				sec = sta->in - hr * 3600 - min * 60;
				sprintf(current->conn_time, "%02d:%02d:%02d", hr, min, sec);

				if(debug) CONN_DEBUG("%s[%3d,BRCM] %02X%02X%02X%02X%02X%02X wl:%d %d, rx %s tx %s rssi %d conn_time %s\n", 
							_CONNLOG_, ii, current->mac[0], current->mac[1], current->mac[2], 
							current->mac[3], current->mac[4], current->mac[5], current->wireless, unit,
							current->rxrate, current->txrate, current->rssi, current->conn_time);
#else
				if(debug) CONN_DEBUG("%s[%3d,BRCM] %02X%02X%02X%02X%02X%02X rssi %d\n", 
							_CONNLOG_, ii, current->mac[0], current->mac[1], current->mac[2], 
							current->mac[3], current->mac[4], current->mac[5], current->rssi);
#endif
				current->next = NULL;
				if(head == NULL)
					head = current;
				else
					prev->next = current;

				prev = current;
			}
		}
	}

	/* error/exit */
exit:
	if (auth) free(auth);
}

static void get_BRCM_stainfo()
{
	int ii = 0;
	char word[256], *next;

	if(debug) CONN_DEBUG("BRCM stainfo start\n");
	foreach (word, nvram_safe_get("wl_ifnames"), next)
	{
#ifdef RTCONFIG_QTN
		if(ii > 0) break;
#endif
		BRCM_stainfo(ii);
		ii++;
	}
}
#endif
#endif

#ifdef RTCONFIG_QTN
static void get_QTN_stainfo(const char *ifname)
{
	if(debug) CONN_DEBUG("QTN stainfo start\n");
	int ret = 0;
	int index = -1;
	int unit = 1;
	char prefix[] = "wlXXXXXXXXXX_";
	char buf[18];
	int i, rssi;

	qcsapi_unsigned_int association_count = 0;
	qcsapi_mac_addr sta_address;
	qcsapi_unsigned_int tx_phy_rate, rx_phy_rate, time_associated;
	int hr, min, sec;

	if (!rpc_qtn_ready()) return;

	sscanf(ifname, "wifi%d", &index);
	if (index == -1) return;
	else if (index == 0)
		sprintf(prefix, "wl%d_", unit);
	else
		sprintf(prefix, "wl%d.%d_", unit, index);

	ret = qcsapi_wifi_get_count_associations(ifname, &association_count);
	if (ret < 0) {
		dbG("Qcsapi qcsapi_wifi_get_count_associations %s error, return: %d\n", ifname, ret);
		return;
	} else {
		for (i = 0; i < association_count; ++i) {
			rssi = 0;
			ret = qcsapi_wifi_get_associated_device_mac_addr(ifname, i, (uint8_t *) &sta_address);
			if (ret < 0) {
				dbG("Qcsapi qcsapi_wifi_get_associated_device_mac_addr %s error, return: %d\n", ifname, ret);
				return;
			} else {
				
				/* linked list */
				log_s *current;
				current = (struct log_info *)malloc(sizeof(struct log_info));
				/* initial */
				memset(current, 0x00, sizeof(struct log_info));

				// mac
				strncpy(current->mac, &sta_address, 6);
				//QTN handle 5G band
				current->wireless = 2;

				ret = qcsapi_wifi_get_rssi_in_dbm_per_association(ifname, i, &rssi);
				if (ret < 0)
					dbG("Qcsapi qcsapi_wifi_get_rssi_in_dbm_per_association %s error, return: %d\n", ifname, ret);
				current->rssi = rssi;
#ifdef RTCONFIG_STAINFO
				/* wireless log */
 				tx_phy_rate = rx_phy_rate = time_associated = 0;

				ret = qcsapi_wifi_get_tx_phy_rate_per_association(ifname, i, &tx_phy_rate);
				if (ret < 0)
					dbG("Qcsapi qcsapi_wifi_get_tx_phy_rate_per_association %s error, return: %d\n", ifname, ret);
				ret = qcsapi_wifi_get_rx_phy_rate_per_association(ifname, i, &rx_phy_rate);
				if (ret < 0)
					dbG("Qcsapi qcsapi_wifi_get_rx_phy_rate_per_association %s error, return: %d\n", ifname, ret);
				ret = qcsapi_wifi_get_time_associated_per_association(ifname, i, &time_associated);
				if (ret < 0)
					dbG("Qcsapi qcsapi_wifi_get_time_associated_per_association %s error, return: %d\n", ifname, ret);

				hr = time_associated / 3600;
				min = (time_associated % 3600) / 60;
				sec = time_associated - hr * 3600 - min * 60;
				snprintf(current->txrate, sizeof(current->txrate), "%d", tx_phy_rate);
				snprintf(current->rxrate, sizeof(current->rxrate), "%d", rx_phy_rate);
				snprintf(current->conn_time, sizeof(current->conn_time), "%02d:%02d:%02d", hr, min, sec);

				if(debug) CONN_DEBUG("%s[%3d,QTN] %02X%02X%02X%02X%02X%02X wl:%d %d, rx %s tx %s rssi %d conn_time %s\n", 
							_CONNLOG_, i, current->mac[0], current->mac[1], current->mac[2], 
							current->mac[3], current->mac[4], current->mac[5], current->wireless, unit,
							current->rxrate, current->txrate, current->rssi, current->conn_time);
#else
				if(debug) CONN_DEBUG("%s[%3d,QTN] %02X%02X%02X%02X%02X%02X, rssi %d\n", 
							_CONNLOG_, i, current->mac[0], current->mac[1], current->mac[2], 
							current->mac[3], current->mac[4], current->mac[5], current->rssi);
#endif


				current->next = NULL;
				if(head == NULL)
					head = current;
				else
					prev->next = current;

				prev = current;
			}
		}
	}
}
#endif

void print_list()
{
	log_s *current;
	current = head;
	
	while(current != NULL)
	{
		CONN_DEBUG("%02X%02X%02X%02X%02X%02X\n", current->mac[0], current->mac[1], current->mac[2], current->mac[3], current->mac[4], current->mac[5]);

		current = current->next;
	}
}

void free_list()
{
	log_s *current;

	while (head != NULL) {
		current = head;
		head = head->next;
		free(current);
	}
	prev = NULL;
}

void find_wireless_device(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int offline)
{
	int i;
	/* debug */
	if(f_exists(_DEBUG_)) debug = 1;
	else debug = 0;

	if(debug) CONN_DEBUG("%s read wireless connections offline check %d\n", _CONNLOG_, offline);

#ifdef RTCONFIG_RALINK
	get_MTK_stainfo();
#else
#ifdef RTCONFIG_QCA
	get_QCA_stainfo(); 
#else
	get_BRCM_stainfo();
#endif
#endif

#ifdef RTCONFIG_QTN
	int unit;
	char tmp[128], prefix[] = "wlXXXXXXXXXX_";

	// QTN main wifi
	get_QTN_stainfo(WIFINAME);

	// QTN guest network
	for (i = 1; i < 4; i++) {
		unit = 1;
		sprintf(prefix, "wl%d.%d_", unit, i);
		if (nvram_match(strcat_r(prefix, "bss_enabled", tmp), "1")){
			get_QTN_stainfo(wl_vifname_qtn(unit, i));
		}
	}
#endif
	if(!offline) {
		log_s *current;
		current = head;
		while(current != NULL)
		{
			if(!memcmp(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->detail_info_num], current->mac, 6)) {
				p_client_detail_info_tab->wireless[p_client_detail_info_tab->detail_info_num] = current->wireless;
				strlcpy(p_client_detail_info_tab->txrate[p_client_detail_info_tab->detail_info_num], current->txrate,
						sizeof(p_client_detail_info_tab->txrate[p_client_detail_info_tab->detail_info_num]));
				strlcpy(p_client_detail_info_tab->rxrate[p_client_detail_info_tab->detail_info_num], current->rxrate,
						sizeof(p_client_detail_info_tab->rxrate[p_client_detail_info_tab->detail_info_num]));
				p_client_detail_info_tab->rssi[p_client_detail_info_tab->detail_info_num] = current->rssi;
				strlcpy(p_client_detail_info_tab->conn_time[p_client_detail_info_tab->detail_info_num], current->conn_time,
						sizeof(p_client_detail_info_tab->conn_time[p_client_detail_info_tab->detail_info_num]));
#if defined(BRTAC828)
				p_client_detail_info_tab->subunit[p_client_detail_info_tab->detail_info_num] = current->subunit;
#endif
				if(debug) CONN_DEBUG("###%d client wl: %d, rx %s tx %s rssi %d conn_time %s \n" 
							, p_client_detail_info_tab->detail_info_num
							, p_client_detail_info_tab->wireless[p_client_detail_info_tab->detail_info_num]
							, p_client_detail_info_tab->rxrate[p_client_detail_info_tab->detail_info_num]
							, p_client_detail_info_tab->txrate[p_client_detail_info_tab->detail_info_num]
							, p_client_detail_info_tab->rssi[p_client_detail_info_tab->detail_info_num]
							, p_client_detail_info_tab->conn_time[p_client_detail_info_tab->detail_info_num]
							);
				break;
			}
			current = current->next;
		}
	}
	else {
		int wireless_check = 0;
		log_s *current;
		for(i = 0; i < p_client_detail_info_tab->detail_info_num; i++) {
			if(p_client_detail_info_tab->wireless[i]) {
				if(debug) CONN_DEBUG(" ###%d wireless client check: %02x%02x%02x%02x%02x%02x \n", i, 
							p_client_detail_info_tab->mac_addr[i][0], 
							p_client_detail_info_tab->mac_addr[i][1],
							p_client_detail_info_tab->mac_addr[i][2],
							p_client_detail_info_tab->mac_addr[i][3],
							p_client_detail_info_tab->mac_addr[i][4],
							p_client_detail_info_tab->mac_addr[i][5]);
				current = head;
				while(current != NULL)
				{
					if(!memcmp(p_client_detail_info_tab->mac_addr[i], current->mac, 6)) {
						p_client_detail_info_tab->wireless[i] = current->wireless;
						strlcpy(p_client_detail_info_tab->txrate[i], current->txrate, sizeof(p_client_detail_info_tab->txrate[i]));
						strlcpy(p_client_detail_info_tab->rxrate[i], current->rxrate, sizeof(p_client_detail_info_tab->rxrate[i]));
						strlcpy(p_client_detail_info_tab->conn_time[i], current->conn_time, sizeof(p_client_detail_info_tab->conn_time[i]));
						if(debug) CONN_DEBUG("### check: %d client wireless: %d\n", i, p_client_detail_info_tab->wireless[i]);
						wireless_check = 1;
						break;
					}
					current = current->next;
				}
				if(!wireless_check) {
					if(debug) CONN_DEBUG("### %d client leave! wireless: %d\n", i, p_client_detail_info_tab->wireless[i]);
					p_client_detail_info_tab->device_flag[i] &= (~(1<<FLAG_EXIST));
				}
			}
		}
	}

	if(debug) print_list();

	free_list();
}
