#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <shutils.h>	  // for eval()
#include <rtstate.h>
#include <bcmnvram.h>
#include <stdlib.h>
#include <asm/byteorder.h>
#include <networkmap.h>
//#include "endianness.h"
//2011.02 Yau add shard memory
#include <sys/ipc.h>
#include <sys/shm.h>
#include <rtconfig.h>
//#include "asusdiscovery.h"
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
#include <bwdpi.h>
#endif
#ifdef RTCONFIG_NOTIFICATION_CENTER
#include <libnt.h>
int TRIGGER_FLAG;
#endif

#include <json.h>


#define vstrsep(buf, sep, args...) _vstrsep(buf, sep, args, NULL)

unsigned char my_hwaddr[6];
// LAN gateway
struct in_addr my_ipaddr_he;	/* router_addr_ne in host endian */
uint32_t my_ipaddr_ne;

CLIENT_DETAIL_INFO_TABLE *p_client_detail_info_tab;
int arp_sockfd;

#ifdef RTCONFIG_TAGGED_BASED_VLAN
//VLAN gateway
unsigned char vlan_ipaddr[8][4];
CLIENT_DETAIL_INFO_TABLE *vlan_client_detail_info_tab[8];
int vlan_arp_sockfd[8];
int vlan_flag = 0;		//record valid vlan subnet
#endif

#ifdef RTCONFIG_CAPTIVE_PORTAL
unsigned char fw_ipaddr[4], cp_ipaddr[4];
CLIENT_DETAIL_INFO_TABLE *fw_client_detail_info_tab, *cp_client_detail_info_tab;
int fw_arp_sockfd, cp_arp_sockfd;
int fw_flag = 0, cp_flag = 0;
#endif

unsigned char broadcast_hwaddr[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
int networkmap_fullscan, lock, mdns_lock, nvram_lock;
int scan_count=0;
//Rawny: save client_list in memory
FILE *fp_ncl; //nmp_client_list FILE
/* add vendor attribute */

#ifdef NMP_DB
char *nmp_client_list;
//Rawny: save client_list in memory
FILE *fp_ncl; //nmp_client_list FILE
struct json_object *nmp_cl_json;
#endif
int delete_sig;
int show_info;

#ifdef PROTOCOL_QUERY
FILE *fp_upnp, *fp_smb;
#endif

//oui json DB
struct json_object *oui_obj;
static int oui_enable = 0;

//signature
extern convType convTypes[];
extern convType bwdpiTypes[];
extern convType vendorTypes[];
//state machine for define device type
ac_state *acType, *dpiType, *vendorType;

#ifdef RTCONFIG_BONJOUR
typedef struct mDNSClientList_struct mDNSClientList;
struct mDNSClientList_struct
{
	unsigned char IPaddr[255][4];
	char Name[255][32];
	char Model[255][16];
};
mDNSClientList *shmClientList;

struct apple_model_handler {
	char *phototype;
	char *model;
	char *type;
};

struct apple_name_handler {
	char *name;
	char *type;
};

struct upnp_type_handler {
	char *server;
	char *type;
};

struct apple_model_handler apple_model_handlers[] = {
	{ "k68ap",	"iPhone",	"10" },
	{ "n82ap",	"iPhone 3G",	"10" },
	{ "n88ap",	"iPhone 3GS",	"10" },
	{ "n90ap",	"iPhone 4",	"10" },
	{ "n90bap",	"iPhone 4",	"10" },
	{ "n92ap",	"iPhone 4",	"10" },
	{ "n41ap",	"iPhone 5",	"10" },
	{ "n42ap",	"iPhone 5",	"10" },
	{ "n48ap",	"iPhone 5c",	"10" },
	{ "n49ap",	"iPhone 5c",	"10" },
	{ "n51ap",	"iPhone 5s",	"10" },
	{ "n53ap",	"iPhone 5s",	"10" },
	{ "n61ap",	"iPhone 6",	"10" },
	{ "n56ap",	"iPhone 6 Plus","10" },
	{ "n71ap",	"iPhone 6s",	"10" },
	{ "n71map",	"iPhone 6s",	"10" },
	{ "n66ap",	"iPhone 6s Plus","10" },
	{ "n66map",	"iPhone 6s Plus","10" },
	{ "n69ap",	"iPhone SE",	"10" },
	{ "n45ap",	"iPod touch",	"21" },
	{ "n72ap",	"iPod touch 2G","21" },
	{ "n18ap",	"iPod touch 3G","21" },
	{ "n81ap",	"iPod touch 4G","21" },
	{ "n78ap",	"iPod touch 5G","21" },
	{ "n78aap",	"iPod touch 5G","21" },
	{ "n102ap",	"iPod touch 6G","21" },
	{ "K48ap",	"iPad",		"21" },
	{ "K93ap",	"iPad 2",	"21" },
	{ "k94ap",	"iPad 2",	"21" },
	{ "k95ap",	"iPad 2",	"21" },
	{ "k93aap",	"iPad 2",	"21" },
	{ "j1ap",	"iPad 3",	"21" },
	{ "j2ap",	"iPad 3",	"21" },
	{ "j2aap",	"iPad 3",	"21" },
	{ "p101ap",	"iPad 4",	"21" },
	{ "p102ap",	"iPad 4",	"21" },
	{ "p103ap",	"iPad 4",	"21" },
	{ "j71ap",	"iPad Air",	"21" },
	{ "j72ap",	"iPad Air",	"21" },
	{ "j73ap",	"iPad Air",	"21" },
	{ "j81ap",	"iPad Air 2",	"21" },
	{ "j82ap",	"iPad Air 2",	"21" },
	{ "j98ap",	"iPad Pro",	"21" },
	{ "j99ap",	"iPad Pro",	"21" },
	{ "j127ap",	"iPad Pro",	"21" },
	{ "j128ap",	"iPad Pro",	"21" },
	{ "p105ap",	"iPad mini 1G",	"21" },
	{ "p106ap",	"iPad mini 1G",	"21" },
	{ "p107ap",	"iPad mini 1G",	"21" },
	{ "j85ap",	"iPad mini 2",	"21" },
	{ "j86ap",	"iPad mini 2",	"21" },
	{ "j87ap",	"iPad mini 2",	"21" },
	{ "j85map",	"iPad mini 3",	"21" },
	{ "j86map",	"iPad mini 3",	"21" },
	{ "j87map",	"iPad mini 3",	"21" },
	{ "j96ap",	"iPad mini 4",	"21" },
	{ "j97ap",	"iPad mini 4",	"21" },
	{ "k66ap",	"Apple TV 2G",	"11" },
	{ "j33ap",	"Apple TV 3G",	"11" },
	{ "j33iap",	"Apple TV 3G",	"11" },
	{ "j42dap",	"Apple TV 4G",	"11" },
	{ "rt288x",	"AiCam",	"5"  },
	{ NULL,		NULL,		NULL }
};

struct apple_name_handler apple_name_handlers[] = {
	{ "iPhone",	"10" },
	{ "MacBook",	"6"  },
	{ "MacMini",	"14" },
	{ "NAS-M25",	"4"  },
	{ "QNAP-TS210",	"4"  },
	{ NULL,		NULL }
};
#endif

#ifdef RTCONFIG_UPNPC
struct upnp_type_handler upnp_type_handlers[] = {
	{"Windows",	"1" },
	{NULL,		NULL}
};
#endif

extern void toLowerCase(char *str);
extern Device_name_filter(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x);


/******** Build ARP Socket Function *********/
struct sockaddr_ll src_sockll, dst_sockll;

#ifdef RTCONFIG_TAGGED_BASED_VLAN
struct sockaddr_ll vlan_dst_sockll[8];
#endif

#ifdef RTCONFIG_CAPTIVE_PORTAL
struct sockaddr_ll fw_dst_sockll, cp_dst_sockll;
#endif

#ifdef RTCONFIG_NOTIFICATION_CENTER
void
call_notify_center(int sort, int event)
{
	extern int TRIGGER_FLAG;
	if(!(TRIGGER_FLAG>>sort & 1)){
		NOTIFY_EVENT_T *event_t = initial_nt_event();
		event_t->event = event;
		//snprintf(event_t->msg, sizeof(event_t->msg), "TRIGGER event: %08x", event);
		snprintf(event_t->msg, sizeof(event_t->msg), "");
		NMP_DEBUG("NT_CENTER: Send event ID:%08x !\n", event_t->event);
		send_trigger_event(event_t);
		nt_event_free(event_t);
		TRIGGER_FLAG |= (1<<sort);
		NMP_DEBUG("check TRIGGER_FLAG %d\n", TRIGGER_FLAG);
	}
}
#endif

void set_arp_timeout(struct timeval *timeout, time_t tv_sec, suseconds_t tv_usec)
{
	timeout->tv_sec = tv_sec;
	timeout->tv_usec = tv_usec;
}

CLIENT_DETAIL_INFO_TABLE *set_client_table_shm(CLIENT_DETAIL_INFO_TABLE *client_table, key_t key)
{
	int lock;
	int shm_id;

	//Initial Shared Memory
	//client tables
	lock = file_lock("networkmap");
	shm_id = shmget((key_t)key, sizeof(CLIENT_DETAIL_INFO_TABLE), 0666|IPC_CREAT);
	if (shm_id == -1){
		fprintf(stderr,"client info shmget failed\n");
		file_unlock(lock);
		exit(1);
	}

	client_table = (P_CLIENT_DETAIL_INFO_TABLE)shmat(shm_id,(void *) 0,0);
	client_table = (P_CLIENT_DETAIL_INFO_TABLE)shmat(shm_id,(void *) 0,0);
	memset(client_table, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
	client_table->ip_mac_num = 0;
	client_table->detail_info_num = 0;
	file_unlock(lock);
	return client_table;
}

static int
iface_get_id(int fd, const char *device)
{
	struct ifreq	ifr;
	memset(&ifr, 0, sizeof(ifr));
	//iface NULL protection
	if (!device) {
		perror("iface_get_id ERR:\n");
		return -1;
	}
	NMP_DEBUG("interface %s\n", device);
	strlcpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));
	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		perror("iface_get_id ERR:\n");
		return -1;
	}

	return ifr.ifr_ifindex;
}
/*
 *  Bind the socket associated with FD to the given device.
 */
static int
iface_bind(int fd, int ifindex)
{
	int			err;
	socklen_t		errlen = sizeof(err);

	memset(&src_sockll, 0, sizeof(src_sockll));
	src_sockll.sll_family	       = AF_PACKET;
	src_sockll.sll_ifindex	       = ifindex;
	src_sockll.sll_protocol        = htons(ETH_P_ARP);

	if (bind(fd, (struct sockaddr *) &src_sockll, sizeof(src_sockll)) == -1) {
		perror("bind device ERR:\n");
		return -1;
	}
	/* Any pending errors, e.g., network is down? */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == -1) {
		return -2;
	}
	if (err > 0) {
		return -2;
	}
	int alen = sizeof(src_sockll);
	if (getsockname(fd, (struct sockaddr*)&src_sockll, (socklen_t *)&alen) == -1) {
		perror("getsockname");
		exit(2);
	}
	if (src_sockll.sll_halen == 0) {
		NMP_DEBUG("Interface is not ARPable (no ll address)\n");
		exit(2);
	}

	return 0;
}

int create_socket(char *device)
{
	/* create UDP socket */
	int sock_fd, device_id;
	sock_fd = socket(PF_PACKET, SOCK_DGRAM, 0);

	if(sock_fd < 0) 
		perror("create socket ERR:");

	device_id = iface_get_id(sock_fd, device);

	if (device_id == -1) {
		NMP_DEBUG("iface_get_id REEOR\n");
		return -1;
	}

	if ( iface_bind(sock_fd, device_id) < 0) {
		NMP_DEBUG("iface_bind ERROR\n");
		return -1;
	}

	return sock_fd;
}

int  sent_arppacket(int raw_sockfd, unsigned char * src_ipaddr, unsigned char * dst_ipaddr, struct sockaddr_ll dst)
{
	ARP_HEADER * arp;
	char raw_buffer[46];

	memset(dst.sll_addr, -1, sizeof(dst.sll_addr));  // set dmac addr FF:FF:FF:FF:FF:FF																		 
	if (raw_buffer == NULL)
	{
		perror("ARP: Oops, out of memory\r");
		return 1;
	}															   
	bzero(raw_buffer, 46);

	// Allow 14 bytes for the ethernet header
	arp = (ARP_HEADER *)(raw_buffer);// + 14);
	arp->hardware_type =htons(DIX_ETHERNET);
	arp->protocol_type = htons(IP_PACKET);
	arp->hwaddr_len = 6;
	arp->ipaddr_len = 4;
	arp->message_type = htons(ARP_REQUEST);
	// My hardware address and IP addresses
	memcpy(arp->source_hwaddr, my_hwaddr, sizeof(arp->source_hwaddr));
	memcpy(arp->source_ipaddr, src_ipaddr, sizeof(arp->source_ipaddr));
	// Destination hwaddr and dest IP addr
	memcpy(arp->dest_hwaddr, broadcast_hwaddr, sizeof(arp->source_hwaddr));
	memcpy(arp->dest_ipaddr, dst_ipaddr, sizeof(arp->source_ipaddr));

	if( (sendto(raw_sockfd, raw_buffer, 46, 0, (struct sockaddr *)&dst, sizeof(dst))) < 0 )
	{
		perror("sendto");
		return 1;
	}
	//NMP_DEBUG("Send ARP Request success to: .%d.%d\n", (int *)dst_ipaddr[2],(int *)dst_ipaddr[3]);
	return 0;
}
/******* End of Build ARP Socket Function ********/

/*********** Signal function **************/
static void refresh_sig(int signo)
{
	NMP_DEBUG("Refresh network map!\n");
	networkmap_fullscan = 1;
	scan_count = 0;	
	nvram_set("networkmap_status", "1");
	nvram_set("networkmap_fullscan", "1");

#if 0
	//reset exixt ip table
	memset(&client_detail_info_tab, 0x00, sizeof(client_detail_info_tabLE));
	p_client_detail_info_tab->num = 0;
	//remove file;
	ret = eval("rm", "/var/networkmap.dat");
#endif
}

static void safe_leave(int signo)
{
#ifdef PROTOCOL_QUERY
	fclose(fp_upnp);
	fclose(fp_smb);
#endif
	file_unlock(lock);
	file_unlock(mdns_lock);
	file_unlock(nvram_lock);
#ifdef NMP_DB
	free(nmp_client_list);
#endif
	free_ac_state(acType);
	free_ac_state(dpiType);
	shmdt(p_client_detail_info_tab);
	if(oui_enable) json_object_put(oui_obj);
	json_object_put(nmp_cl_json);
	close(arp_sockfd);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
	int i;
	if(vlan_flag){
		for(i = 0; i < 8; i++){
			if(vlan_flag & (1<<i)){
				shmdt(vlan_client_detail_info_tab[i]);
				close(vlan_arp_sockfd[i]);
			}
		}
	}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
	if(fw_flag == 1){
		shmdt(fw_client_detail_info_tab);
		close(fw_arp_sockfd);
	}
	if(cp_flag == 1){
		shmdt(cp_client_detail_info_tab);
		close(cp_arp_sockfd);
	}
#endif

	NMP_DEBUG("Leave......\n");
}

#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIRELESSREPEATER)
char *getStaMAC()
{
	char buf[512];
	FILE *fp;
	int len,unit;
	char *pt1,*pt2;
	unit=nvram_get_int("wlc_band");

	sprintf(buf, "ifconfig sta%d", unit);

	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, sizeof(buf));
		len = fread(buf, 1, sizeof(buf), fp);
		pclose(fp);
		if (len > 1) {
			buf[len-1] = '\0';
			pt1 = strstr(buf, "HWaddr ");
			if (pt1)
			{
				pt2 = pt1 + strlen("HWaddr ");
				chomp(pt2);
				return pt2;
			}
		}
	}
	return NULL;
}
#endif

void
convert_mac_to_string(unsigned char *mac, char *mac_str)
{
	sprintf(mac_str, "%02x%02x%02x%02x%02x%02x",
			*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
}

void
convert_mac_to_upper_oui_string(unsigned char *mac, char *mac_str)
{
	sprintf(mac_str, "%02X%02X%02X",
			*mac,*(mac+1),*(mac+2));
}

#ifdef NMP_DB
int commit_no = 0;
int client_updated = 0;

int
check_nmp_db(CLIENT_DETAIL_INFO_TABLE *p_client_tab, int client_no)
{
	char new_mac[13];
	char *search_list, *nv, *nvp, *b;
	char *db_mac, *db_user_def, *db_device_name, *db_type, *db_http, *db_printer, *db_itune, *db_apple_model, *db_vendor;
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
	char *db_bwdpi_host, *db_bwdpi_vendor, *db_bwdpi_type, *db_bwdpi_device;
#endif
#endif
	int ret = 0;

	NMP_DEBUG("check_nmp_db:\n");
	search_list = strdup(nmp_client_list);
	convert_mac_to_string(p_client_tab->mac_addr[client_no], new_mac);

	//NMP_DEBUG("search_list= %s\n", search_list);
	if(strstr(search_list, new_mac)==NULL) {
		free(search_list);
		return ret;
	}

	nvp = nv = search_list;

	while (nv && (b = strsep(&nvp, "<")) != NULL) {
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
		if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune, &db_bwdpi_host, &db_bwdpi_vendor, &db_bwdpi_type, &db_bwdpi_device) != 12) continue;
#else
		if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune) != 8) continue; 
#endif
#endif 
		if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune, &db_vendor) != 9) 
			continue;
		
		NMP_DEBUG_M("DB:-%s,%s,%s,%s,%s,%s,%s,%s,%s-\n", db_mac, db_user_def, db_device_name, db_apple_model, db_type, db_http, db_printer, 
				db_itune, db_vendor);
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
		//NMP_DEBUG_M("BWDPI:-%s,%s-\n", db_bwdpi_hostname, db_bwdpi_devicetype);
#endif
#endif

		if (!strcmp(db_mac, new_mac)) {
			NMP_DEBUG("%s at DB!!! Update to memory & device flag is %d\n",new_mac, p_client_tab->device_flag[client_no]);
			strlcpy((char *)p_client_tab->user_define[client_no], db_user_def, sizeof (p_client_tab->user_define[client_no]));
			strlcpy((char *)p_client_tab->vendor_name[client_no], db_vendor, sizeof (p_client_tab->vendor_name[client_no]));
			strlcpy((char *)p_client_tab->device_name[client_no], db_device_name, sizeof (p_client_tab->device_name[client_no]));
			strlcpy((char *)p_client_tab->apple_model[client_no], db_apple_model, sizeof (p_client_tab->apple_model[client_no]));
			p_client_tab->type[client_no] = atoi(db_type);
			//set http flag from DB
			p_client_tab->device_flag[client_no] &= (~(1<<FLAG_HTTP)); 
			p_client_tab->device_flag[client_no] |= (atoi(db_http)<<FLAG_HTTP);
			//set printer flag from DB
			p_client_tab->device_flag[client_no] &= (~(1<<FLAG_PRINTER));
			p_client_tab->device_flag[client_no] |= (atoi(db_printer)<<FLAG_PRINTER);
			//set itune flag from DB
			p_client_tab->device_flag[client_no] &= (~(1<<FLAG_ITUNE));
			p_client_tab->device_flag[client_no] |= (atoi(db_itune)<<FLAG_ITUNE);
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
			strlcpy(p_client_tab->bwdpi_host[client_no], db_bwdpi_host, sizeof (p_client_tab->bwdpi_host[client_no]));
			strlcpy(p_client_tab->bwdpi_vendor[client_no], db_bwdpi_vendor, sizeof (p_client_tab->bwdpi_vendor[client_no]));
			strlcpy(p_client_tab->bwdpi_type[client_no], db_bwdpi_type, sizeof (p_client_tab->bwdpi_type[client_no]));
			strlcpy(p_client_tab->bwdpi_device[client_no], db_bwdpi_device, sizeof (p_client_tab->bwdpi_device[client_no]));
#endif
#endif
			ret = 1;
			break;
		}
	}

	free(search_list);

	return ret;
}

void
write_to_DB(CLIENT_DETAIL_INFO_TABLE *p_client_tab, struct json_object *clients)
{
	char new_mac[13], mac_buf[32], *dst_list, *dst_list_tmp;
	char *nv, *nvp, *b, *search_list;
	char *db_mac, *db_user_def, *db_device_name, *db_type, *db_http, *db_printer, *db_itune, *db_apple_model, *db_vendor;
	struct json_object *client;
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
	char *db_bwdpi_host, *db_bwdpi_vendor, *db_bwdpi_type, *db_bwdpi_device;
#endif
#endif

	memset(mac_buf, 0, sizeof(mac_buf));
	sprintf(mac_buf, "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_tab->mac_addr[p_client_tab->detail_info_num][0],p_client_tab->mac_addr[p_client_tab->detail_info_num][1],
			p_client_tab->mac_addr[p_client_tab->detail_info_num][2],p_client_tab->mac_addr[p_client_tab->detail_info_num][3],
			p_client_tab->mac_addr[p_client_tab->detail_info_num][4],p_client_tab->mac_addr[p_client_tab->detail_info_num][5]);


	convert_mac_to_string(p_client_tab->mac_addr[p_client_tab->detail_info_num], new_mac);

	NMP_DEBUG("write_to_memory: %s\n",new_mac);
	search_list = strdup(nmp_client_list);

	b = strstr(search_list, new_mac);
	if(b!=NULL) { //find the client in the DB
		dst_list = malloc(sizeof(char)*(strlen(nmp_client_list)+SINGLE_CLIENT_SIZE)+1);
		dst_list_tmp = malloc(sizeof(char)*(strlen(nmp_client_list)+SINGLE_CLIENT_SIZE)+1);
		NMP_DEBUG_M("client data in DB: %s\n", new_mac);

		nvp = nv = b;
		*(b-1) = '\0';
		strcpy(dst_list, search_list);
		//b++;
		while (nv && (b = strsep(&nvp, "<")) != NULL) {
			if (b == NULL) continue;
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
			if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune, &db_bwdpi_host, &db_bwdpi_vendor, &db_bwdpi_type, &db_bwdpi_device) != 12) continue;
#else
			if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune) != 8) continue;
#endif
#endif
			if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune, 
					&db_vendor) != 9) continue;

			NMP_DEBUG_M("-%s,%s,%s,%s,%d,%d,%d,%d,%s-\n", db_mac, db_user_def, db_device_name, db_apple_model, atoi(db_type), atoi(db_http), 
					atoi(db_printer), atoi(db_itune), db_vendor);
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
			NMP_DEBUG_M("BWDPI: %s,%s,%s,%s\n", db_bwdpi_host, db_bwdpi_vendor, db_bwdpi_type, db_bwdpi_device);
#endif
#endif
			if (!strcmp((char *)p_client_tab->device_name[p_client_tab->detail_info_num], db_device_name) &&
					!strcmp((char *)p_client_tab->vendor_name[p_client_tab->detail_info_num], db_vendor) &&
					!strcmp((char *)p_client_tab->apple_model[p_client_tab->detail_info_num], db_apple_model) &&
					p_client_tab->type[p_client_tab->detail_info_num] == atoi(db_type) &&
					!((p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<<FLAG_HTTP)) ^ (atoi(db_http)<<FLAG_HTTP)) &&
					!((p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<<FLAG_PRINTER)) ^ (atoi(db_http)<<FLAG_PRINTER)) &&
					!((p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<<FLAG_ITUNE)) ^ (atoi(db_http)<<FLAG_ITUNE))
/*
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
					&& !strcmp(p_client_tab->bwdpi_host[p_client_tab->detail_info_num], db_bwdpi_host)
					&& !strcmp(p_client_tab->bwdpi_vendor[p_client_tab->detail_info_num], db_bwdpi_vendor)
					&& !strcmp(p_client_tab->bwdpi_type[p_client_tab->detail_info_num], db_bwdpi_type)
					&& !strcmp(p_client_tab->bwdpi_device[p_client_tab->detail_info_num], db_bwdpi_device)
#endif
*/
			   )
			{
				NMP_DEBUG("DATA the same!\n");
				free(dst_list);
				free(search_list);
				return;
			}
			sprintf(dst_list_tmp, "%s<%s>%s", dst_list, db_mac, db_user_def);
			strcpy(dst_list, dst_list_tmp);

			if (strcmp((char *)p_client_tab->device_name[p_client_tab->detail_info_num], "")) {
				client_updated = 1;
				NMP_DEBUG("Update device name: %s.\n", p_client_tab->device_name[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%s", dst_list, p_client_tab->device_name[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_device_name);
			strcpy(dst_list, dst_list_tmp);

			if (strcmp((char *)p_client_tab->apple_model[p_client_tab->detail_info_num], "")) {
				client_updated = 1;
				NMP_DEBUG("Update Apple device: %s.\n", p_client_tab->apple_model[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%s", dst_list, p_client_tab->apple_model[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_apple_model);
			strcpy(dst_list, dst_list_tmp);

			if (p_client_tab->type[p_client_tab->detail_info_num] != 0) {
				client_updated = 1;
				NMP_DEBUG("Update type: %d\n", p_client_tab->type[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%d", dst_list, p_client_tab->type[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_type);
			strcpy(dst_list, dst_list_tmp);

			if (!strcmp(db_http, "0") ) {
				client_updated = 1;
				NMP_DEBUG("Update http: %d\n", (p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_HTTP))?1:0);
				sprintf(dst_list_tmp, "%s>%d", dst_list, (p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_HTTP))?1:0);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_http);
			strcpy(dst_list, dst_list_tmp);

			if (!strcmp(db_printer, "0") ) {
				client_updated = 1;
				NMP_DEBUG("Update printer: %d\n", (p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_PRINTER))?1:0);
				sprintf(dst_list_tmp, "%s>%d", dst_list, (p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_PRINTER))?1:0);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_printer);
			strcpy(dst_list, dst_list_tmp);

			if (!strcmp(db_itune, "0")) {
				client_updated = 1;
				NMP_DEBUG("Update iTune: %d\n", (p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_ITUNE))?1:0);
				sprintf(dst_list_tmp, "%s>%d", dst_list, (p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_ITUNE))?1:0);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_itune);
			strcpy(dst_list, dst_list_tmp);
			
			if (strcmp((char *)p_client_tab->vendor_name[p_client_tab->detail_info_num], "")) {
				client_updated = 1;
				NMP_DEBUG("Update vendor name: %s.\n", p_client_tab->vendor_name[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%s", dst_list, p_client_tab->vendor_name[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_vendor);
			strcpy(dst_list, dst_list_tmp);

#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
			if (strcmp(p_client_tab->bwdpi_host[p_client_tab->detail_info_num], "")) {
				client_updated = 1;
				NMP_DEBUG("Update bwdpi_host: %s.\n", p_client_tab->bwdpi_host[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%s", dst_list, p_client_tab->bwdpi_host[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_bwdpi_host);
			strcpy(dst_list, dst_list_tmp);

			if (strcmp(p_client_tab->bwdpi_vendor[p_client_tab->detail_info_num], "")) {
				client_updated = 1;
				NMP_DEBUG("Update bwdpi_vendor: %s.\n", p_client_tab->bwdpi_vendor[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%s", dst_list, p_client_tab->bwdpi_vendor[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_bwdpi_vendor);
			strcpy(dst_list, dst_list_tmp);

			if (strcmp(p_client_tab->bwdpi_type[p_client_tab->detail_info_num], "")) {
				client_updated = 1;
				NMP_DEBUG("Update bwdpi_type: %s.\n", p_client_tab->bwdpi_type[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%s", dst_list, p_client_tab->bwdpi_type[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_bwdpi_type);
			strcpy(dst_list, dst_list_tmp);

			if (strcmp(p_client_tab->bwdpi_device[p_client_tab->detail_info_num], "")) {
				client_updated = 1;
				NMP_DEBUG("Update bwdpi_device: %s.\n", p_client_tab->bwdpi_device[p_client_tab->detail_info_num]);
				sprintf(dst_list_tmp, "%s>%s", dst_list, p_client_tab->bwdpi_device[p_client_tab->detail_info_num]);
			}
			else
				sprintf(dst_list_tmp, "%s>%s", dst_list, db_bwdpi_device);
			strcpy(dst_list, dst_list_tmp);
#endif
#endif
			NMP_DEBUG_M("nv %s\n nvp:%s\n b:%s\n dist_list:%s\n", nv, nvp, b, dst_list);
			if(nvp != NULL) {
				strcat(dst_list, "<");
				strcat(dst_list, nvp);
			}
			nmp_client_list = realloc(nmp_client_list, sizeof(char)*(strlen(dst_list)+1));
			strcpy(nmp_client_list, dst_list);
			NMP_DEBUG_M("Update nmp_client_list:\n%s\n", nmp_client_list);
			break;

			/* json networkmap client list database */
			if(client = json_object_object_get(clients, mac_buf)) {
				json_object_object_del(clients, mac_buf);
			}
			client = json_object_new_object();
			json_object_object_add(client, "type", json_object_new_int(p_client_tab->type[p_client_tab->detail_info_num]));
			json_object_object_add(client, "mac", json_object_new_string(mac_buf));
			json_object_object_add(client, "name", json_object_new_string(p_client_tab->device_name[p_client_tab->detail_info_num]));
			json_object_object_add(client, "vendor", json_object_new_string(p_client_tab->vendor_name[p_client_tab->detail_info_num]));
			json_object_object_add(clients, mac_buf, client);
		}
		free(dst_list);
		free(dst_list_tmp);
	}
	else { //new client
		nmp_client_list = realloc(nmp_client_list, sizeof(char)*(strlen(search_list)+SINGLE_CLIENT_SIZE)+1);
		dst_list_tmp = malloc(sizeof(char)*(strlen(search_list)+SINGLE_CLIENT_SIZE)+1);
		if (strlen(search_list))
			strcpy(nmp_client_list, search_list);
		NMP_DEBUG_M("new client: %d-%s,%s,%d\n",p_client_tab->detail_info_num,
				new_mac,
				p_client_tab->device_name[p_client_tab->detail_info_num],
				p_client_tab->type[p_client_tab->detail_info_num]);

		sprintf(dst_list_tmp,"%s<%s>>%s>%s>%d>%d>%d>%d>%s", nmp_client_list, 
				new_mac,
				p_client_tab->device_name[p_client_tab->detail_info_num],
				p_client_tab->apple_model[p_client_tab->detail_info_num],
				p_client_tab->type[p_client_tab->detail_info_num],
				(p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_HTTP))?1:0,
				(p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_PRINTER))?1:0,
				(p_client_tab->device_flag[p_client_tab->detail_info_num] & (1<FLAG_ITUNE))?1:0,
				p_client_tab->vendor_name[p_client_tab->detail_info_num]
			);
		strcpy(nmp_client_list, dst_list_tmp);
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
		sprintf(dst_list_tmp,"%s>%s>%s>%s>%s", nmp_client_list,
				p_client_tab->bwdpi_host[p_client_tab->detail_info_num],
				p_client_tab->bwdpi_vendor[p_client_tab->detail_info_num],
				p_client_tab->bwdpi_type[p_client_tab->detail_info_num],
				p_client_tab->bwdpi_device[p_client_tab->detail_info_num]);
		strcpy(nmp_client_list, dst_list_tmp);
#endif
#endif
		
		free(dst_list_tmp);

		/* json networkmap client list database */
		client = json_object_new_object();
		json_object_object_add(client, "type", json_object_new_int(p_client_tab->type[p_client_tab->detail_info_num]));
		json_object_object_add(client, "mac", json_object_new_string(mac_buf));
		json_object_object_add(client, "name", json_object_new_string(p_client_tab->device_name[p_client_tab->detail_info_num]));
		json_object_object_add(client, "vendor", json_object_new_string(p_client_tab->vendor_name[p_client_tab->detail_info_num]));
		json_object_object_add(clients, mac_buf, client);
	}

	free(search_list);
}

int
DeletefromDB(CLIENT_DETAIL_INFO_TABLE *p_client_tab, struct json_object *clients)
{
	char *mac_str, mac_buf[32];
	char *dst_list;
	char *nv, *nvp, *b, *search_list;
	char *db_mac, *db_user_def, *db_device_name, *db_type, *db_http, *db_printer, *db_itune, *db_apple_model, *db_vendor;
	struct json_object *client;
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
	char *db_bwdpi_host, *db_bwdpi_vendor, *db_bwdpi_type, *db_bwdpi_device;
#endif
#endif
	int del_ret = 0;

	mac_str = p_client_tab->delete_mac;
	NMP_DEBUG("delete_from_memory: %s\n%s\n", mac_str, nmp_client_list);
	memset(mac_buf, 0, sizeof(mac_buf));
	sprintf(mac_buf, "%C%C:%C%C:%C%C:%C%C:%C%C:%C%C",
			toupper(*mac_str), toupper(*(mac_str+1)), toupper(*(mac_str+2)), toupper(*(mac_str+3)), toupper(*(mac_str+4)), toupper(*(mac_str+5)), 
			toupper(*(mac_str+6)), toupper(*(mac_str+7)), toupper(*(mac_str+8)), toupper(*(mac_str+9)), toupper(*(mac_str+10)), 
			toupper(*(mac_str+11)), toupper(*(mac_str+12)));
	NMP_DEBUG("#json delete_from_memory: %s\n", mac_buf);

	search_list = strdup(nmp_client_list);

	b = strstr(search_list, mac_str);
	if(b!=NULL) { //find the client in the DB
		dst_list = malloc(sizeof(char)*(strlen(nmp_client_list)+1));
		NMP_DEBUG_M("client data in DB: %s\n", mac_str);

		nvp = nv = b;
		*(b-1) = '\0';
		strcpy(dst_list, search_list);
		//b++;
		while (nv && (b = strsep(&nvp, "<")) != NULL) {
			if (b == NULL) continue;
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
			if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune, &db_bwdpi_host, &db_bwdpi_vendor, &db_bwdpi_type, &db_bwdpi_device) != 12) continue;
#else
			if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune) != 8) continue;
#endif
#endif
			if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune
					, &db_vendor) != 9) continue;

			NMP_DEBUG_M("-%s,%s,%s,%s,%d,%d,%d,%d,%s-\n", db_mac, db_user_def, db_device_name, db_apple_model, atoi(db_type), atoi(db_http), atoi(db_printer), atoi(db_itune), db_vendor);
#if 0
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
			NMP_DEBUG_M("BWDPI: %s,%s,%s,%s\n", db_bwdpi_host, db_bwdpi_vendor, db_bwdpi_type, db_bwdpi_device);
#endif
#endif
			NMP_DEBUG("nv %s\n nvp:%s\n b:%s\n dist_list:%s\n", nv, nvp, b, dst_list);
			if(nvp != NULL) {
				strcat(dst_list, "<");
				strcat(dst_list, nvp);
			}
			nmp_client_list = realloc(nmp_client_list, sizeof(char)*(strlen(dst_list)+1));
			strlcpy(nmp_client_list, dst_list, strlen(dst_list)+1);
			/* json networkmap client list database */
			if(client = json_object_object_get(clients, mac_buf)) {
				json_object_object_del(clients, mac_buf);
			}
			NMP_DEBUG_M("Update nmp_client_list:\n%s\n", nmp_client_list);
			del_ret = 1; 
			break;
		}
		free(dst_list);
	}

	free(search_list);
	memset(p_client_tab->delete_mac, 0, sizeof(p_client_tab->delete_mac));	
	return del_ret;
}

void
check_nmp_db_format() {
	char *nv, *nvp, *b, *search_list;
	char *db_mac, *db_user_def, *db_device_name, *db_type, *db_http, *db_printer, *db_itune, *db_apple_model, *db_vendor;
	
	search_list = strdup(nmp_client_list);
	b = search_list;
	if(b!=NULL) {
		nvp = nv = b;
		*(b-1) = '\0';
		//b++;
		while (nv && (b = strsep(&nvp, "<")) != NULL) {
			if (b == NULL) continue;
			if (vstrsep(b, ">", &db_mac, &db_user_def, &db_device_name, &db_apple_model, &db_type, &db_http, &db_printer, &db_itune
					, &db_vendor) != 9) {
				free(nmp_client_list);
				nmp_client_list = malloc(sizeof(char)*SINGLE_CLIENT_SIZE);
				eval("rm", NMP_CLIENT_LIST_FILENAME);
				break;
			}
		}
	}
	free(search_list);
}

void
reset_db() {
	NMP_DEBUG("RESET DB!!!\n");
	if ((fp_ncl=fopen(NMP_CLIENT_LIST_FILENAME, "w"))) {
		fclose(fp_ncl);
	}
	memset(nmp_client_list, 0, strlen(nmp_client_list)+1);	
	refresh_sig(0);
}
void
delete_sig_on(int signo) {
	NMP_DEBUG("DELETE OFFLINE CLIENT FROM DB!!!\n");
	delete_sig = 1;
}
#endif

void
show_client_info() {
	show_info = 1;
}

#ifdef RTCONFIG_BONJOUR
static void AppleModelCheck(char *model, char *name, unsigned char *type, char *shm_model)
{
	struct apple_model_handler *model_handler;
	struct apple_name_handler *name_handler;

	for (model_handler = &apple_model_handlers[0]; model_handler->phototype; model_handler++) {
		if((shm_model != NULL) && strstr(shm_model, model_handler->phototype))
		{
			strcpy(model, model_handler->model);
			*type =  atoi(model_handler->type);
			NMP_DEBUG_M("1. Apple Check get model=%s, type=%d\n", model, *type);
			return;
		}
	}
	for (name_handler = &apple_name_handlers[0]; name_handler->name; name_handler++) {
		if((name != NULL) && strstr(name, name_handler->name))
		{
			*type =  atoi(name_handler->type);
			NMP_DEBUG_M("2. Apple Check name=%s, find type=%d\n", name, *type);
			break;
		}
	}

	return;
}
#endif

#ifdef RTCONFIG_UPNPC
static int QuerymUPnPCInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x)
{
	char search_list[128], client_ip[16];
	char *nv, *nvp, *b;
	char *upnpc_ip, *upnpc_type, *upnpc_friendlyname;
	struct upnp_type_handler *upnp_handler;
	FILE *fp;

	sprintf(client_ip, "%d.%d.%d.%d",
	p_client_detail_info_tab->ip_addr[x][0],
	p_client_detail_info_tab->ip_addr[x][1],
	p_client_detail_info_tab->ip_addr[x][2],
	p_client_detail_info_tab->ip_addr[x][3]);

	if( (fp = fopen("/tmp/miniupnpc.log", "r")) != NULL )
	{
		while( fgets(search_list, sizeof(search_list), fp) )
		{
			if( strstr(search_list, client_ip) )
			{
				nvp = nv = search_list;
				while (nv && (b = strsep(&nvp, "<")) != NULL) {
					if (vstrsep(b, ">", &upnpc_ip, &upnpc_type, &upnpc_friendlyname) != 3) 
						continue;
				}

				if(p_client_detail_info_tab->type[x] == 0) {
					for (upnp_handler = &upnp_type_handlers[0]; upnp_handler->server; upnp_handler++) {
						if(!strcmp(upnpc_type, upnp_handler->server))
						{
							NMP_DEBUG("MiniUPnP get type!!! %s = %s\n", upnpc_type, upnp_handler->type);
							p_client_detail_info_tab->type[x] = atoi(upnp_handler->type);
							break;
						}
					}
				}

				
				if(p_client_detail_info_tab->device_name[x] == NULL) {
					if((strcmp(upnpc_friendlyname, "") && !strstr(upnpc_friendlyname, "UPnP Access Point"))) {
						NMP_DEBUG("MiniUPnP get name: %s\n", upnpc_friendlyname);
						strlcpy(p_client_detail_info_tab->device_name[x], upnpc_friendlyname, sizeof(p_client_detail_info_tab->device_name[x]));
					}
				}
			}
		}
		fclose(fp);
	}
}
#endif

#ifdef RTCONFIG_BONJOUR
static int QuerymDNSInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x)
{
	unsigned char *a;
	int i;

	/*
	   printf("mDNS Query: %d?%d: %d.%d.%d.%d\n", x,
	   p_client_detail_info_tab->ip_mac_num,
	   p_client_detail_info_tab->ip_addr[x][0],
	   p_client_detail_info_tab->ip_addr[x][1],
	   p_client_detail_info_tab->ip_addr[x][2],
	   p_client_detail_info_tab->ip_addr[x][3]
	   );
	 */
	mdns_lock = file_lock("mDNSNetMonitor");

	i = 0;
	while (shmClientList->IPaddr[i][0] != '\0' && i < ARRAY_SIZE(shmClientList->IPaddr) ) {
		a = shmClientList->IPaddr[i];
		if(!memcmp(a,p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num],4)) {
			NMP_DEBUG_M("Query mDNS get: %d, %d.%d.%d.%d/%s/%s_\n", i,
					a[0],a[1],a[2],a[3], shmClientList->Name[i], shmClientList->Model[i]);
			if(shmClientList->Name[i]!=NULL && strcmp(shmClientList->Name[i],p_client_detail_info_tab->device_name[x]))
				strlcpy(p_client_detail_info_tab->device_name[x], shmClientList->Name[i], sizeof(p_client_detail_info_tab->device_name[x]));
			if(shmClientList->Model[i]!=NULL && strcmp(shmClientList->Name[i],p_client_detail_info_tab->apple_model[x]))
				toLowerCase(shmClientList->Model[i]);
			AppleModelCheck(p_client_detail_info_tab->apple_model[x],
					p_client_detail_info_tab->device_name[x],
					&p_client_detail_info_tab->type[x],
					shmClientList->Model[i]);
			break;
		}
		i++;
	}

	file_unlock(mdns_lock);

	return 0;
}
#endif

void StringChk(char *chk_string)
{
	char *ptr = chk_string;
	while(*ptr!='\0') {
		if(*ptr<0x20 || *ptr>0x7E)
			*ptr = ' ';
		ptr++;
	}
}

#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
static int QueryBwdpiInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int x)
{
	bwdpi_device bwdpi_dev_info;
	char mac[18];
	int typeID = 0;
	char *host2lower;
	int spType = 0;

	sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_detail_info_tab->mac_addr[x][0],
			p_client_detail_info_tab->mac_addr[x][1],
			p_client_detail_info_tab->mac_addr[x][2],
			p_client_detail_info_tab->mac_addr[x][3],
			p_client_detail_info_tab->mac_addr[x][4],
			p_client_detail_info_tab->mac_addr[x][5]
	       );
	NMP_DEBUG("Bwdpi Query: %s\n", mac);

	if(bwdpi_client_info(mac, &bwdpi_dev_info)) {
		NMP_DEBUG("  Get: %s/%s/%s/%s\n", bwdpi_dev_info.hostname, bwdpi_dev_info.vendor_name,
				bwdpi_dev_info.type_name, bwdpi_dev_info.device_name);
		strlcpy(p_client_detail_info_tab->bwdpi_host[x], bwdpi_dev_info.hostname, sizeof(p_client_detail_info_tab->bwdpi_host[x]));
		strlcpy(p_client_detail_info_tab->bwdpi_vendor[x], bwdpi_dev_info.vendor_name, sizeof(p_client_detail_info_tab->bwdpi_vendor[x]));
		strlcpy(p_client_detail_info_tab->bwdpi_type[x], bwdpi_dev_info.type_name, sizeof(p_client_detail_info_tab->bwdpi_type[x]));
		strlcpy(p_client_detail_info_tab->bwdpi_device[x], bwdpi_dev_info.device_name, sizeof(p_client_detail_info_tab->bwdpi_device[x]));
		StringChk(p_client_detail_info_tab->bwdpi_host[x]);
		StringChk(p_client_detail_info_tab->bwdpi_vendor[x]);
		StringChk(p_client_detail_info_tab->bwdpi_type[x]);
		StringChk(p_client_detail_info_tab->bwdpi_device[x]);
		if (strcmp((char *)p_client_detail_info_tab->bwdpi_host[x], "")) {
			strlcpy(p_client_detail_info_tab->device_name[x], p_client_detail_info_tab->bwdpi_host[x], 
				sizeof(p_client_detail_info_tab->device_name[x]));
			Device_name_filter(p_client_detail_info_tab, x);
			NMP_DEBUG("*** Add BWDPI host %s\n", p_client_detail_info_tab->device_name[x]);
		}
		if (strcmp((char *)p_client_detail_info_tab->bwdpi_device[x], "")) {
			strlcpy(p_client_detail_info_tab->apple_model[x], p_client_detail_info_tab->bwdpi_device[x], 
				sizeof(p_client_detail_info_tab->apple_model[x]));
			if (strcmp((char *)p_client_detail_info_tab->device_name[x], "")) {
				host2lower = strdup(p_client_detail_info_tab->device_name[x]);
				toLowerCase(host2lower);
				if (strstr(host2lower, "android")) {
					strlcpy(p_client_detail_info_tab->device_name[x], p_client_detail_info_tab->bwdpi_device[x], 
						sizeof(p_client_detail_info_tab->device_name[x]));
					if((typeID = prefix_search(dpiType, p_client_detail_info_tab->bwdpi_device[x])))
					p_client_detail_info_tab->type[x] = typeID;
					NMP_DEBUG("*** BWDPI_DEVICE Find device type %d\n", typeID);
				}
				free(host2lower);
			}
			NMP_DEBUG("*** Add BWDPI device model %s\n", p_client_detail_info_tab->apple_model[x]);     
		}
		if (!strcmp((char *)p_client_detail_info_tab->vendor_name[x], "") && strcmp((char *)p_client_detail_info_tab->bwdpi_vendor[x], "")) {
			strlcpy(p_client_detail_info_tab->vendor_name[x], p_client_detail_info_tab->bwdpi_vendor[x],
				sizeof(p_client_detail_info_tab->vendor_name[x]));
			NMP_DEBUG("*** Add BWDPI vendor %s\n", p_client_detail_info_tab->vendor_name[x]);
		}
		if(!p_client_detail_info_tab->type[x] || p_client_detail_info_tab->type[x] == 34 || p_client_detail_info_tab->type[x] == 9 
		|| p_client_detail_info_tab->type[x] == 23 || p_client_detail_info_tab->type[x] == 20)
			spType = 1;
		if(spType == 1 && strcmp((char *)p_client_detail_info_tab->bwdpi_device[x], "")) {
			if((typeID = full_search(dpiType, p_client_detail_info_tab->bwdpi_device[x]))) {
				p_client_detail_info_tab->type[x] = typeID;
				NMP_DEBUG("*** BWDPI_DEVICE Find device type %d\n", typeID);
			}
		}
		if(!p_client_detail_info_tab->type[x] && strcmp((char *)p_client_detail_info_tab->bwdpi_type[x], "")) {
			if((typeID = prefix_search(dpiType, p_client_detail_info_tab->bwdpi_type[x]))) {
				p_client_detail_info_tab->type[x] = typeID;
				NMP_DEBUG("*** BWDPI_TYPE Find device type %d\n", typeID);
			}
		}
		if(!p_client_detail_info_tab->type[x] && strcmp((char *)p_client_detail_info_tab->bwdpi_host[x], "")) {
			host2lower = strdup(p_client_detail_info_tab->bwdpi_host[x]);
			toLowerCase(host2lower);
			if((typeID = full_search(acType, host2lower))) {
				p_client_detail_info_tab->type[x] = typeID;
				NMP_DEBUG("*** BWDPI_HOST Find device type %d\n", typeID);
			}
			free(host2lower);
		}

		NMP_DEBUG("bwdpi info: %d, %s, %s, %S\n", p_client_detail_info_tab->type[x], 
				p_client_detail_info_tab->bwdpi_device[x], p_client_detail_info_tab->bwdpi_type[x], p_client_detail_info_tab->bwdpi_host[x]);

#ifdef RTCONFIG_NOTIFICATION_CENTER
		if(p_client_detail_info_tab->type[x] == 7)
			call_notify_center(FLAG_XBOX_PS, HINT_XBOX_PS_EVENT);
		if(p_client_detail_info_tab->type[x] == 27)
			call_notify_center(FLAG_UPNP_RENDERER, HINT_UPNP_RENDERER_EVENT);
		if(p_client_detail_info_tab->type[x] == 6)
			call_notify_center(FLAG_OSX_INLAN, HINT_OSX_INLAN_EVENT);
#endif
	}

	return 0;
}
#endif

#if 1
void
swap_asus_device(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int i)
{
	unsigned char buffer[100];
	//swap ip address
	memcpy(buffer, p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->asus_device_num], 
			sizeof(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->asus_device_num]));
	memcpy(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->ip_addr[i], 
			sizeof(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->asus_device_num]));
	memcpy(p_client_detail_info_tab->ip_addr[i], buffer, sizeof(p_client_detail_info_tab->ip_addr[i]));
	//swap mac address
	memcpy(buffer, p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->asus_device_num], 
			sizeof(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->asus_device_num]));
	memcpy(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->mac_addr[i], 
			sizeof(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->asus_device_num]));
	memcpy(p_client_detail_info_tab->mac_addr[i], buffer, sizeof(p_client_detail_info_tab->mac_addr[i]));
	//swap user defined name
	strlcpy(buffer, p_client_detail_info_tab->user_define[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->user_define[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->user_define[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->user_define[i],
			sizeof(p_client_detail_info_tab->user_define[i]));
	strlcpy(p_client_detail_info_tab->user_define[i], buffer, sizeof(p_client_detail_info_tab->user_define[i]));
	//swap vendor name
	strlcpy(buffer, p_client_detail_info_tab->vendor_name[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->vendor_name[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->vendor_name[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->vendor_name[i],
			sizeof(p_client_detail_info_tab->vendor_name[i]));
	strlcpy(p_client_detail_info_tab->vendor_name[i], buffer, sizeof(p_client_detail_info_tab->vendor_name[i]));
	//swap device name
	strlcpy(buffer, p_client_detail_info_tab->device_name[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->device_name[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->device_name[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->device_name[i],
			sizeof(p_client_detail_info_tab->device_name[i]));
	strlcpy(p_client_detail_info_tab->device_name[i], buffer, sizeof(p_client_detail_info_tab->device_name[i]));
	//swap apple model
	strlcpy(buffer, p_client_detail_info_tab->apple_model[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->apple_model[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->apple_model[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->apple_model[i],
			sizeof(p_client_detail_info_tab->apple_model[i]));
	strlcpy(p_client_detail_info_tab->apple_model[i], buffer, sizeof(p_client_detail_info_tab->apple_model[i]));
	//XOR swap
	p_client_detail_info_tab->type[p_client_detail_info_tab->asus_device_num] ^= p_client_detail_info_tab->type[i];
	p_client_detail_info_tab->type[i] ^= p_client_detail_info_tab->type[p_client_detail_info_tab->asus_device_num];
	p_client_detail_info_tab->type[p_client_detail_info_tab->asus_device_num] ^= p_client_detail_info_tab->type[i];
	p_client_detail_info_tab->device_flag[p_client_detail_info_tab->asus_device_num] ^= p_client_detail_info_tab->device_flag[i];
	p_client_detail_info_tab->device_flag[i] ^= p_client_detail_info_tab->device_flag[p_client_detail_info_tab->asus_device_num];
	p_client_detail_info_tab->device_flag[p_client_detail_info_tab->asus_device_num] ^= p_client_detail_info_tab->device_flag[i];
	p_client_detail_info_tab->wireless[p_client_detail_info_tab->asus_device_num] ^= p_client_detail_info_tab->wireless[i];
	p_client_detail_info_tab->wireless[i] ^= p_client_detail_info_tab->wireless[p_client_detail_info_tab->asus_device_num];
	p_client_detail_info_tab->wireless[p_client_detail_info_tab->asus_device_num] ^= p_client_detail_info_tab->wireless[i];
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
	strlcpy(buffer, p_client_detail_info_tab->bwdpi_host[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->bwdpi_host[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->bwdpi_host[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->bwdpi_host[i],
			sizeof(p_client_detail_info_tab->bwdpi_host[i]));
	strlcpy(p_client_detail_info_tab->bwdpi_host[i], buffer, sizeof(p_client_detail_info_tab->bwdpi_host[i]));
	strlcpy(buffer, p_client_detail_info_tab->bwdpi_vendor[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->bwdpi_vendor[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->bwdpi_vendor[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->bwdpi_vendor[i],
			sizeof(p_client_detail_info_tab->bwdpi_vendor[i]));
	strlcpy(p_client_detail_info_tab->bwdpi_vendor[i], buffer, sizeof(p_client_detail_info_tab->bwdpi_vendor[i]));
	strlcpy(buffer, p_client_detail_info_tab->bwdpi_type[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->bwdpi_type[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->bwdpi_type[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->bwdpi_type[i],
			sizeof(p_client_detail_info_tab->bwdpi_type[i]));
	strlcpy(p_client_detail_info_tab->bwdpi_type[i], buffer, sizeof(p_client_detail_info_tab->bwdpi_type[i]));
	strlcpy(buffer, p_client_detail_info_tab->bwdpi_device[p_client_detail_info_tab->asus_device_num],
			sizeof(p_client_detail_info_tab->bwdpi_device[p_client_detail_info_tab->asus_device_num]));
	strlcpy(p_client_detail_info_tab->bwdpi_device[p_client_detail_info_tab->asus_device_num], p_client_detail_info_tab->bwdpi_device[i],
			sizeof(p_client_detail_info_tab->bwdpi_device[i]));
	strlcpy(p_client_detail_info_tab->bwdpi_device[i], buffer, sizeof(p_client_detail_info_tab->bwdpi_device[i]));
#endif
	NMP_DEBUG("**** check asus device number %d\n", p_client_detail_info_tab->asus_device_num);
}
#endif

void
QueryAsusOuiInfo(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, int i)
{
	char dev_mac[18], dev_oui_mac[7];
	char *search_list, *nv, *nvp, *b;
	char *dummy, *asus_ProductID, *asus_IP, *asus_Mac, *dummy2, *asus_SSID, *asus_subMask, *asus_type;
	char *IPCam, *mac;
	int index = 0;
	unsigned char tmpType;

	NMP_DEBUG("check_asus_discovery:\n");
	search_list = strdup(nvram_get("asus_device_list"));
	mac = p_client_detail_info_tab->mac_addr[i];
	sprintf(dev_mac, "%02X:%02X:%02X:%02X:%02X:%02X",
			p_client_detail_info_tab->mac_addr[i][0],
			p_client_detail_info_tab->mac_addr[i][1],
			p_client_detail_info_tab->mac_addr[i][2],
			p_client_detail_info_tab->mac_addr[i][3],
			p_client_detail_info_tab->mac_addr[i][4],
			p_client_detail_info_tab->mac_addr[i][5]);

	NMP_DEBUG("search MAC= %s\n", dev_mac);

	nvp = nv = search_list;

	if(strstr(search_list, dev_mac)!=NULL) {
		while (nv && (b = strsep(&nvp, "<")) != NULL) {
			if (vstrsep(b, ">", &dummy, &asus_ProductID, &asus_IP, &asus_Mac, &dummy2, &asus_SSID, &asus_subMask, &asus_type) != 8) continue;

			//NMP_DEBUG("Find MAC in Asus Discovery: %s, %s, %s, %s, %s, %s, %s, %s", dummy, asus_ProductID, asus_IP, asus_Mac, dummy2, asus_SSID, asus_subMask, &asus_type);
			if(!strcmp(asus_Mac, dev_mac)) {
				IPCam = strdup(asus_ProductID);
				toLowerCase(IPCam);
				if(strstr(IPCam, "cam")) {
					p_client_detail_info_tab->type[i] = 5;
					NMP_DEBUG("***** Find AiCam****\n");
				}
				else if(asus_type != "")
				{
					tmpType = atoi(asus_type);
					if(tmpType == 2)
						p_client_detail_info_tab->type[i] = 24;
					else
						p_client_detail_info_tab->type[i] = 2;
				}
	
				strlcpy(p_client_detail_info_tab->device_name[i], asus_ProductID, sizeof(p_client_detail_info_tab->device_name[i]));
				strlcpy(p_client_detail_info_tab->vendor_name[i], "Asus", sizeof(p_client_detail_info_tab->vendor_name[i]));
				strlcpy(p_client_detail_info_tab->ssid[i], asus_SSID, sizeof(p_client_detail_info_tab->ssid[i]));
				p_client_detail_info_tab->opMode[i] = atoi(asus_type);
				p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_HTTP);
				free(IPCam);
				NMP_DEBUG("asus device: %d, %s, opMode:%d\n", p_client_detail_info_tab->type[i], p_client_detail_info_tab->device_name[i], 
						p_client_detail_info_tab->opMode[i]);
#if 1
				if(i != p_client_detail_info_tab->asus_device_num)
					swap_asus_device(p_client_detail_info_tab, i);
#endif
				p_client_detail_info_tab->asus_device_num++;
				break;
			}
		}
	}
	else if(oui_enable){
		NMP_DEBUG("check_oui_json_db:\n");
		//if not found in asus discovery, fill in oui info
		struct json_object *vendor_obj;
		char *vendor_str = NULL;
		convert_mac_to_upper_oui_string(mac, dev_oui_mac);
		vendor_obj = json_object_object_get(oui_obj, dev_oui_mac);
		if((vendor_str = json_object_get_string(vendor_obj))) {
			if(index = prefix_search_index(vendorType, vendor_str)) {
				strlcpy(p_client_detail_info_tab->device_name[i], vendor_str, index);
				strlcpy(p_client_detail_info_tab->vendor_name[i], vendor_str, index);
				NMP_DEBUG("*** Find Favous OUI %s\n", p_client_detail_info_tab->vendor_name[i]);
			}
			else {
				strlcpy(p_client_detail_info_tab->device_name[i], vendor_str, sizeof(p_client_detail_info_tab->device_name[i]));
				strlcpy(p_client_detail_info_tab->vendor_name[i], vendor_str, sizeof(p_client_detail_info_tab->device_name[i]));
			}
		}
	}
		
	free(search_list);
}

void
handle_client_list(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab, char *buf, unsigned char *src_ip, int scanCount)
{
	int i, lock;
	ARP_HEADER * arp_ptr;
	unsigned short msg_type;
	int ip_dup, mac_dup;
	int chk_DB_ret;

	arp_ptr = (ARP_HEADER*)(buf);

	//Check ARP packet if source ip and router ip at the same network
	if( !memcmp(src_ip, arp_ptr->source_ipaddr, 3) ) {
		msg_type = ntohs(arp_ptr->message_type);

		if( //ARP packet to router
			( msg_type == 0x02 &&					// ARP response
			  memcmp(arp_ptr->dest_ipaddr, src_ip, 4) == 0 &&	// dest IP
			  memcmp(arp_ptr->dest_hwaddr, my_hwaddr, 6) == 0)	// dest MAC
			||
			(msg_type == 0x01 &&					// ARP request
			  memcmp(arp_ptr->dest_ipaddr, src_ip, 4) == 0)		// dest IP
		){
			//NMP_DEBUG("	It's an ARP Response to Router!\n");
			NMP_DEBUG("*RCV %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X,%d,%02x,IP:%d\n",
					arp_ptr->source_ipaddr[0],arp_ptr->source_ipaddr[1],
					arp_ptr->source_ipaddr[2],arp_ptr->source_ipaddr[3],
					arp_ptr->source_hwaddr[0],arp_ptr->source_hwaddr[1],
					arp_ptr->source_hwaddr[2],arp_ptr->source_hwaddr[3],
					arp_ptr->source_hwaddr[4],arp_ptr->source_hwaddr[5], scanCount, msg_type, p_client_detail_info_tab->ip_mac_num);

			for(i = 0; i < p_client_detail_info_tab->ip_mac_num; i++) {
				ip_dup = memcmp(p_client_detail_info_tab->ip_addr[i], arp_ptr->source_ipaddr, 4);
				mac_dup = memcmp(p_client_detail_info_tab->mac_addr[i], arp_ptr->source_hwaddr, 6);
				if((ip_dup == 0) && (mac_dup == 0)) {
					lock = file_lock("networkmap");
					p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
					file_unlock(lock);
					break;
				}
				else if((ip_dup != 0) && (mac_dup != 0)) {
					continue;
				}
				else if( (scanCount>=255) && ((ip_dup != 0) && (mac_dup == 0)) ) {
					NMP_DEBUG("IP changed, update immediately\n");
					NMP_DEBUG("*CMP %d.%d.%d.%d-%02X:%02X:%02X:%02X:%02X:%02X\n",
							p_client_detail_info_tab->ip_addr[i][0],p_client_detail_info_tab->ip_addr[i][1],
							p_client_detail_info_tab->ip_addr[i][2],p_client_detail_info_tab->ip_addr[i][3],
							p_client_detail_info_tab->mac_addr[i][0],p_client_detail_info_tab->mac_addr[i][1],
							p_client_detail_info_tab->mac_addr[i][2],p_client_detail_info_tab->mac_addr[i][3],
							p_client_detail_info_tab->mac_addr[i][4],p_client_detail_info_tab->mac_addr[i][5]);
					lock = file_lock("networkmap");
					memcpy(p_client_detail_info_tab->ip_addr[i], arp_ptr->source_ipaddr, sizeof(p_client_detail_info_tab->ip_addr[i]));
					memcpy(p_client_detail_info_tab->mac_addr[i], arp_ptr->source_hwaddr, sizeof(p_client_detail_info_tab->mac_addr[i]));
					p_client_detail_info_tab->device_flag[i] |= (1<<FLAG_EXIST);
					file_unlock(lock);
					break;
				}
			}
			/* i=0, table is empty.
			   i=num, no the same ip at table.*/
			if(i==p_client_detail_info_tab->ip_mac_num){
				lock = file_lock("networkmap");
				memcpy(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num], 
					arp_ptr->source_ipaddr, sizeof(p_client_detail_info_tab->ip_addr[p_client_detail_info_tab->ip_mac_num]));
				memcpy(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->ip_mac_num], 
					arp_ptr->source_hwaddr, sizeof(p_client_detail_info_tab->mac_addr[p_client_detail_info_tab->ip_mac_num]));
				p_client_detail_info_tab->device_flag[p_client_detail_info_tab->ip_mac_num] |= (1<<FLAG_EXIST);

				chk_DB_ret = 0;
//DB query can't reduce search speed anymore, thus shut down
#if 0
#ifdef NMP_DB
				chk_DB_ret = check_nmp_db(p_client_detail_info_tab, i);
				NMP_DEBUG("check DB result: %d\n", chk_DB_ret);
#endif
#endif
				if (!chk_DB_ret) {
#ifdef RTCONFIG_BONJOUR
					QuerymDNSInfo(p_client_detail_info_tab, i);
#endif
#ifdef RTCONFIG_UPNPC
					QuerymUPnPCInfo(p_client_detail_info_tab, i);
#endif
					//Find Asus Device, if not found, fill oui info
					QueryAsusOuiInfo(p_client_detail_info_tab, i);
				}
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
				if(nvram_get_int("sw_mode") == SW_MODE_ROUTER) {
					if(check_bwdpi_nvram_setting()) {
						NMP_DEBUG("BWDPI ON!\n");
						QueryBwdpiInfo(p_client_detail_info_tab, i);
					}
				}
#endif
				FindHostname(p_client_detail_info_tab);
				StringChk(p_client_detail_info_tab->device_name[i]);
				NMP_DEBUG("Fill: %d-> %d.%d.%d.%d\n", i,
						p_client_detail_info_tab->ip_addr[i][0],
						p_client_detail_info_tab->ip_addr[i][1],
						p_client_detail_info_tab->ip_addr[i][2],
						p_client_detail_info_tab->ip_addr[i][3]);

				p_client_detail_info_tab->ip_mac_num++;
				file_unlock(lock);
			}
		}//ARP packet to router
	}//Source IP in the same subnetwork
}

void
handle_detail_client_list(P_CLIENT_DETAIL_INFO_TABLE p_client_detail_info_tab)
{
	int lock;

	if(p_client_detail_info_tab->detail_info_num < p_client_detail_info_tab->ip_mac_num) {
		NMP_DEBUG("Deep Scan !\n");
		nvram_set("networkmap_status", "1");
#ifdef PROTOCOL_QUERY
		FindAllApp(my_ipaddr, p_client_detail_info_tab, p_client_detail_info_tab->detail_info_num);
#endif
		//check wireless device & set flag
		find_wireless_device(p_client_detail_info_tab, 0);
		NMP_DEBUG("wirelesss: %d\n", p_client_detail_info_tab->wireless[p_client_detail_info_tab->detail_info_num]);
		lock = file_lock("networkmap");
		FindHostname(p_client_detail_info_tab);
		if(!strcmp(p_client_detail_info_tab->ipMethod[p_client_detail_info_tab->detail_info_num], "")) {
			NMP_DEBUG("Static client found!\n");
			strlcpy(p_client_detail_info_tab->ipMethod[p_client_detail_info_tab->detail_info_num], "Static", 
				sizeof(p_client_detail_info_tab->ipMethod[p_client_detail_info_tab->detail_info_num]));
		}
		StringChk(p_client_detail_info_tab->device_name[p_client_detail_info_tab->detail_info_num]);
#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
		if(nvram_get_int("sw_mode") == SW_MODE_ROUTER) {
			if(check_bwdpi_nvram_setting()) {
				NMP_DEBUG("BWDPI ON!\n");
				QueryBwdpiInfo(p_client_detail_info_tab, p_client_detail_info_tab->detail_info_num);
			}
		}
#endif
		file_unlock(lock);
#ifdef NMP_DB
		//Rawny: Check if DB memory size will over limit
		if ((NCL_LIMIT - strlen(nmp_client_list)) > SINGLE_CLIENT_SIZE)
			write_to_DB(p_client_detail_info_tab, nmp_cl_json);
#endif
		p_client_detail_info_tab->detail_info_num++;
		NMP_DEBUG_M("Finish Deep Scan no.%d!\n", p_client_detail_info_tab->detail_info_num);
	}
#ifdef NMP_DB
	else {
//		NMP_DEBUG_M("commit_no, cli_no, updated: %d, %d, %d\n", 
//				p_client_detail_info_tab->commit_no, p_client_detail_info_tab->detail_info_num, client_updated);
		if( (p_client_detail_info_tab->commit_no != p_client_detail_info_tab->detail_info_num) || client_updated ) {
			NMP_DEBUG_M("Write to DB file!\n");
			if ((fp_ncl=fopen(NMP_CLIENT_LIST_FILENAME, "w"))) {
				fprintf(fp_ncl, "%s", nmp_client_list);
				fclose(fp_ncl);
			}
			json_object_to_file(NMP_CL_JSON_FILE, nmp_cl_json);
 
			p_client_detail_info_tab->commit_no = p_client_detail_info_tab->detail_info_num;
			client_updated = 0;
			NMP_DEBUG_M("Finish Write to DB file!\n");
		}
	}
#endif
	if(p_client_detail_info_tab->detail_info_num == p_client_detail_info_tab->ip_mac_num) {
#ifdef RTCONFIG_NOTIFICATION_CENTER
		nvram_set_int("networkmap_trigger_flag", TRIGGER_FLAG);
#endif
		lock = file_lock("networkmap");

		/* check if wireless device offline(not in wireless log)
		*/
		if(nvram_match("nmp_wl_offline_check", "1"))	//web server trigger wl offline check
		{
			find_wireless_device(p_client_detail_info_tab, 1);
			//nvram_unset("nmp_wl_offline_check");
		}
		
		file_unlock(lock);
		nvram_set("networkmap_status", "0");		// Done scanning and resolving
	}
}		


/******************************************/
int main(int argc, char *argv[])
{
	int arp_packet_rcv = 0;
	int arp_getlen, max_scan_count;
	struct sockaddr_in router_addr_ne;
	struct in_addr netmask_ne;
	char router_ipaddr[17], router_mac[17], buffer[ARP_BUFFER_SIZE];
	uint32_t scan_ipaddr_he, scan_ipaddr_ne, arp_srcipaddr_ne, netaddr_ne;
	struct timeval *arp_timeout;
#ifdef RTCONFIG_TAGGED_BASED_VLAN
	int vlan_arp_getlen[8];
	char vlan_buffer[8][ARP_BUFFER_SIZE];
	unsigned char vlan_scan_ipaddr[8][4];
	struct sockaddr_in vlan_hw_ipaddr[8];
	int i, j;
	//int same_subnet = 0;
#endif
#if defined(RTCONFIG_TAGGED_BASED_VLAN) || defined(RTCONFIG_CAPTIVE_PORTAL)
	char prefix[32], subnet_ipaddr[20];
	char *netmask;
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
	int fw_arp_getlen, cp_arp_getlen;
	char fw_buffer[ARP_BUFFER_SIZE], cp_buffer[ARP_BUFFER_SIZE];
	//free wifi & cpative portal scan subnet
	unsigned char fw_scan_ipaddr[4], cp_scan_ipaddr[4];
	struct sockaddr_in fw_hw_ipaddr, cp_hw_ipaddr;
#endif
#ifdef RTCONFIG_BONJOUR
	int shm_mdns_id;
#endif
	int lock;
#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIRELESSREPEATER)	
	char *mac;
#endif
	//Rawny: save client_list in memory 
	unsigned int size_ncl; //size of nmp_client_list

	FILE *fp = fopen("/var/run/networkmap.pid", "w");
	if(fp != NULL){
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

#ifdef PROTOCOL_QUERY
	fp_upnp = fopen("/tmp/upnp.log", "w");
	fp_smb = fopen("tmp/smb.log", "w");
#endif

#ifdef NMP_DB
	if ((fp_ncl=fopen(NMP_CLIENT_LIST_FILENAME, "r"))) {
		fseek(fp_ncl, 0L, SEEK_END);
		size_ncl = ftell(fp_ncl);
		NMP_DEBUG("nmp_client_list FILE size %d\n", size_ncl);
		fseek(fp_ncl, 0L, SEEK_SET);
		if (size_ncl && size_ncl < NCL_LIMIT) {
			nmp_client_list = malloc(sizeof(char)*size_ncl+1);
			if (fread(nmp_client_list, 1, size_ncl, fp_ncl) != size_ncl) {
				NMP_DEBUG("Read Client list DB ERR....Reset DB!\n");
				memset(nmp_client_list, 0, NCL_LIMIT);
			} 
			nmp_client_list[size_ncl] = '\0';
			//NMP_DEBUG("Read Client list DB: %s from %s\n", nmp_client_list, NMP_CLIENT_LIST_FILENAME);
			
			//check if networkmap database format is latest version
			check_nmp_db_format();
		}
		else {
			nmp_client_list = malloc(sizeof(char)*SINGLE_CLIENT_SIZE+1);
			NMP_DEBUG("Read Client list DB fail!\nSize is %d...remove oversize file.\n", size_ncl);
			eval("rm", NMP_CLIENT_LIST_FILENAME);				
		}
		fclose(fp_ncl);
	}
	else
		nmp_client_list = malloc((sizeof(char)*SINGLE_CLIENT_SIZE) + 1);

	//signal(SIGUSR2, reset_db);

	/************************************************/
	/* start json networkmap client list DB loading	*/
	if (!(nmp_cl_json = json_object_from_file(NMP_CL_JSON_FILE))) {
		NMP_DEBUG("open networkmap client list json database ERR:\n");
		nmp_cl_json = json_object_new_object();
	}
	/* end json networkmap client list DB loading	*/
	/************************************************/
#endif

	//unset client list nvram DB in older verion
	if (nvram_get("nmp_client_list")){
		nvram_unset("nmp_client_list");
	}

	//Get Router's IP/Mac
	strcpy(router_ipaddr, nvram_safe_get("lan_ipaddr"));
	strcpy(router_mac, get_lan_hwaddr());
#if defined(RTCONFIG_QCA) && defined(RTCONFIG_WIRELESSREPEATER)
#ifndef RTCONFIG_CONCURRENTREPEATER
	if (sw_mode() == SW_MODE_REPEATER && (mac = getStaMAC()) != NULL)
		strncpy(router_mac, mac, sizeof(router_mac));
#endif  /* #ifndef RTCONFIG_CONCURRENTREPEATER */
#endif
#ifdef RTCONFIG_GMAC3
	if(nvram_match("gmac3_enable", "1"))
		strcpy(router_mac, nvram_safe_get("et2macaddr"));
#endif
	inet_aton(router_ipaddr, &router_addr_ne.sin_addr);
	my_ipaddr_he.s_addr = ntohl(router_addr_ne.sin_addr.s_addr);

	//Get maximum scan count via netmask
	max_scan_count = 255;	/* if netmask = 255.255.255.0 */
	if (inet_aton(nvram_get("lan_netmask")? : nvram_default_get("lan_netmask"), &netmask_ne))
		max_scan_count = ~ntohl(netmask_ne.s_addr);	/* omit one IP address as original code. */
	netaddr_ne = router_addr_ne.sin_addr.s_addr & netmask_ne.s_addr;
	scan_ipaddr_he = my_ipaddr_he.s_addr & ~ntohl(netmask_ne.s_addr);
	my_ipaddr_ne = htonl(my_ipaddr_he.s_addr);
	//limit scan range
	if(max_scan_count > 1024) max_scan_count = 1024;
	NMP_DEBUG("check max scan count: %d clients capacity %d\n", max_scan_count, MAX_NR_CLIENT_LIST);

	//Prepare scan 
	networkmap_fullscan = 1;
	nvram_set("networkmap_fullscan", "1");

	if (argc > 1) {
		if (strcmp(argv[1], "--bootwait") == 0) {
			sleep(30);
		}
	}
	if (strlen(router_mac)!=0) ether_atoe(router_mac, my_hwaddr);

	signal(SIGUSR1, refresh_sig); //catch UI refresh signal
	signal(SIGTERM, safe_leave);
	delete_sig = 0;
#ifdef NMP_DB
	signal(SIGUSR2, delete_sig_on);
#endif
	show_info = 0;
	//signal(SIGUSR2, show_client_info);

	// create UDP socket and bind to "br0" to get ARP packet//
	arp_sockfd = create_socket(INTERFACE);

	//arp_timeput initial
	arp_timeout = (struct timeval*)malloc(sizeof(struct timeval));
	memset(arp_timeout, 0, sizeof(struct timeval));
	set_arp_timeout(arp_timeout, 0, 5000);

	if(arp_sockfd < 0)
		perror("create socket ERR:");
	else {
		setsockopt(arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
		//Copy sockaddr info to dst
		memset(&dst_sockll, 0, sizeof(dst_sockll));
		memcpy(&dst_sockll, &src_sockll, sizeof(src_sockll));
		//set LAN subnet share memory
		p_client_detail_info_tab = set_client_table_shm(p_client_detail_info_tab, SHMKEY_LAN);
	}

#ifdef RTCONFIG_BONJOUR
	//mDNSNetMonitor
	mdns_lock = file_lock("mDNSNetMonitor");
	shm_mdns_id = shmget((key_t)SHMKEY_BONJOUR, sizeof(mDNSClientList), 0666|IPC_CREAT);

	if (shm_mdns_id == -1){
		fprintf(stderr,"mDNS shmget failed\n");
		file_unlock(mdns_lock);
		return 0;
	}
	shmClientList = (mDNSClientList *)shmat(shm_mdns_id,(void *) 0,0);
	if (shmClientList == (void *)-1){
		fprintf(stderr,"shmat failed\n");
		file_unlock(mdns_lock);
		return 0;
	}
	file_unlock(mdns_lock);
	//////
#endif

#ifdef RTCONFIG_TAGGED_BASED_VLAN
	lock = file_lock("networkmap");
	if (nvram_match("vlan_enable", "1")){
		NMP_DEBUG("vlan enable\n");
		if (nvram_get_int("vlan_index")){
			NMP_DEBUG("vlan index %d\n", nvram_get_int("vlan_index"));
			int shm_key = 1003;
			for (i = 0; i <= (nvram_get_int("vlan_index") - 3); i++){
				//same_subnet = 0;
				memset(prefix, 0x00, sizeof(prefix));
				snprintf(prefix, sizeof(prefix), "lan%d_subnet", (i + 3));
				NMP_DEBUG("i %d %s\n", i, prefix);
				if (nvram_get(prefix) && !(nvram_match(prefix, "default"))){
					NMP_DEBUG("prefix %s\n", prefix);
					/* set IP of vlan with subnet */
					memset(router_ipaddr, 0x00, sizeof(router_ipaddr));
					memset(subnet_ipaddr, 0x00, sizeof(subnet_ipaddr));
					strcpy(subnet_ipaddr, nvram_safe_get(prefix));
					netmask = strchr(subnet_ipaddr, '/');
					*netmask = '\0';
					strcpy(router_ipaddr, subnet_ipaddr);
					NMP_DEBUG("vlan IP %s!!\n", router_ipaddr);
					inet_aton(router_ipaddr, &vlan_hw_ipaddr[i].sin_addr);
#if 0
					/* check if subnet exists in previous vlan */
					for (j = 0; j < i; j++){
						if (vlan_ipaddr[j] && !memcmp(&vlan_hw_ipaddr[i].sin_addr, vlan_ipaddr[j], 4)){
							same_subnet = 1;
							NMP_DEBUG("find the same subnet %d %d %d %d\n", vlan_ipaddr[j][0], vlan_ipaddr[j][1], vlan_ipaddr[j][2], vlan_ipaddr[j][3]);
							break;
						}
					}
					if (same_subnet)
						continue;
					/*end of check same subnet */
#endif
					memcpy(vlan_ipaddr[i], &vlan_hw_ipaddr[i].sin_addr, sizeof(vlan_ipaddr[i]));
					/* end of setting IP */

					/* create UDP socket and bind to "vlan" to get ARP packet */
					snprintf(prefix, sizeof(prefix), "lan%d_ifname", (i + 3));
					NMP_DEBUG("interface %s\n", prefix);
					vlan_arp_sockfd[i] = create_socket(nvram_get(prefix));
					if(vlan_arp_sockfd[i] < 0)
						perror("create socket ERR:");
					else {
						set_arp_timeout(arp_timeout, 0, 5000);
						setsockopt(vlan_arp_sockfd[i], SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
						//Copy sockaddr info to dst
						memset(&vlan_dst_sockll[i], 0, sizeof(src_sockll));
						memcpy(&vlan_dst_sockll[i], &src_sockll, sizeof(src_sockll));
						/* set vlan subnet client list shm */
						vlan_client_detail_info_tab[i] = set_client_table_shm(vlan_client_detail_info_tab[i], shm_key);
						NMP_DEBUG("tagged vlan%d memory set\n", (i + 3));
						/* end of setting vlan subnet client list shm */
						NMP_DEBUG("vlan %s socket create success!!\n", nvram_get(prefix));
						vlan_flag |= 1<<(i);
					}
					/* end of creating vlan socket */
					shm_key++;
				}//end of if (nvram_get(prefix))
			}//end of for loop
		}//end of if (nvram_get_int("vlan_index"))
	}//end of if (nvram_match("vlan_enable", "1"))
	nvram_set_int("vlan_flag", vlan_flag);
	NMP_DEBUG("***vlan subnet bitmap %d\n", nvram_get_int("vlan_flag"));
	file_unlock(lock);
#endif

#ifdef RTCONFIG_CAPTIVE_PORTAL
	if (nvram_match("captive_portal_enable", "on")){
		/* set IP of free-wifi with subnet */
		memset(router_ipaddr, 0x00, sizeof(router_ipaddr));
		memset(subnet_ipaddr, 0x00, sizeof(subnet_ipaddr));
		strcpy(subnet_ipaddr, nvram_safe_get("chilli_net"));
		netmask = strchr(subnet_ipaddr, '/');
		*netmask = '\0';
		strcpy(router_ipaddr, subnet_ipaddr);
		NMP_DEBUG("free-wifi IP %s!!\n", router_ipaddr);
		inet_aton(router_ipaddr, &fw_hw_ipaddr.sin_addr);
		memcpy(fw_ipaddr, &fw_hw_ipaddr.sin_addr, sizeof(fw_ipaddr));
		/* end of setting IP */

		/* create UDP socket and bind to free-wifi interface to get ARP packet */
		fw_arp_sockfd = create_socket(nvram_get("lan1_ifname"));
		if(fw_arp_sockfd < 0)
			perror("create socket ERR:");
		else {
			set_arp_timeout(arp_timeout, 0, 5000);
			setsockopt(fw_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
			//Copy sockaddr info to dst
			memset(&fw_dst_sockll, 0, sizeof(src_sockll));
			memcpy(&fw_dst_sockll, &src_sockll, sizeof(src_sockll));
			/* set free-wifi subnet client list shm */
			fw_client_detail_info_tab = set_client_table_shm(fw_client_detail_info_tab, SHMKEY_FREEWIFI);
			NMP_DEBUG("free-wifi memory set\n");
			/* end of setting free-wifi subnet client list shm */
			NMP_DEBUG("free-wifi socket create success!!\n");
			fw_flag = 1;
		}
		/* end of creating free-wifi socket */
	}
	if (nvram_match("captive_portal_adv_enable", "on")){
		/* set IP of captive portal with subnet */
		memset(router_ipaddr, 0x00, sizeof(router_ipaddr));
		memset(subnet_ipaddr, 0x00, sizeof(subnet_ipaddr));
		strcpy(subnet_ipaddr, nvram_safe_get("cp_net"));
		netmask = strchr(subnet_ipaddr, '/');
		*netmask = '\0';
		strcpy(router_ipaddr, subnet_ipaddr);
		NMP_DEBUG("Captive portal IP %s!!\n", router_ipaddr);
		inet_aton(router_ipaddr, &cp_hw_ipaddr.sin_addr);
		memcpy(cp_ipaddr, &cp_hw_ipaddr.sin_addr, sizeof(cp_ipaddr));
		/* end of setting IP */

		/* create UDP socket and bind to captive portal interface to get ARP packet */
		cp_arp_sockfd = create_socket(nvram_get("lan2_ifname"));
		if(cp_arp_sockfd < 0)
			perror("create socket ERR:");
		else {
			set_arp_timeout(arp_timeout, 0, 5000);
			setsockopt(cp_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
			//Copy sockaddr info to dst
			memset(&cp_dst_sockll, 0, sizeof(src_sockll));
			memcpy(&cp_dst_sockll, &src_sockll, sizeof(src_sockll));
			/* set captive portal subnet client list shm */
			cp_client_detail_info_tab = set_client_table_shm(cp_client_detail_info_tab, SHMKEY_CP);
			NMP_DEBUG("captive portal memory set\n");
			/* end of setting captive portal subnet client list shm */
			NMP_DEBUG("captive portal socket create success!!\n");
			cp_flag =1;
		}
		/* end of creating captive portal socket */
	}
#endif

	//initial trigger flag
#ifdef RTCONFIG_NOTIFICATION_CENTER
	TRIGGER_FLAG = atoi(nvram_safe_get("networkmap_trigger_flag"));
	if(TRIGGER_FLAG < 0 || TRIGGER_FLAG > 15) TRIGGER_FLAG = 0;
	NMP_DEBUG(" Test networkmap trigger flag >>> %d!\n", TRIGGER_FLAG);	
#endif

	/***********************************/
	/* start json OUI DB loading	   */
	if (!(oui_obj = json_object_from_file(NEWORKMAP_OUI_FILE))) {
		NMP_DEBUG("open OUI database ERR:\n");
	}
	else oui_enable = 1;
	/* end json OUI DB loading	   */
	/***********************************/

	/* load string match automata	   */
	acType = construct_ac_trie(convTypes, NTYPE);
	dpiType = construct_ac_trie(bwdpiTypes, BWDPITYPE);
	vendorType = construct_ac_trie(vendorTypes, VENDORTYPE); 
	/* end of loading automata	   */
	NMP_DEBUG("end of loading automata\n");

	while(1)//main while loop
	{
		while(1) { //full scan and reflush recv buffer
			fullscan:
				if(networkmap_fullscan == 1) { //Scan all IP address in the subnetwork
					if(scan_count == 0) { 
#ifdef RTCONFIG_BONJOUR
						eval("mDNSQuery");	//send mDNS service dicsovery
#endif
						eval("asusdiscovery");	//find asus device
						// (re)-start from the begining
						scan_ipaddr_he = my_ipaddr_he.s_addr & ntohl(netmask_ne.s_addr);
						set_arp_timeout(arp_timeout, 0, 5000);
						setsockopt(arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
						NMP_DEBUG("Starting full scan!\n");
#ifdef RTCONFIG_TAGGED_BASED_VLAN
						if(vlan_flag){
							for(i = 0; i < 8; i++){
								if(vlan_flag & (1<<i)){
									memset(vlan_scan_ipaddr[i], 0x00, sizeof(vlan_scan_ipaddr[i]));
									memcpy(vlan_scan_ipaddr[i], &vlan_hw_ipaddr[i].sin_addr, 3);
									setsockopt(vlan_arp_sockfd[i], SOL_SOCKET, SO_RCVTIMEO, 
										arp_timeout, sizeof(struct timeval));//set receive timeout
									NMP_DEBUG("set vlan %d socket option\n", (i + 3));
								}
							}
						}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
						if (fw_flag == 1){
							memset(fw_scan_ipaddr, 0x00, sizeof(fw_scan_ipaddr));
							memcpy(fw_scan_ipaddr, &fw_hw_ipaddr.sin_addr, 3);
							NMP_DEBUG("set free-wifi socket option\n");
						}
						if (cp_flag == 1){
							memset(cp_scan_ipaddr, 0x00, sizeof(cp_scan_ipaddr));
							memcpy(cp_scan_ipaddr, &cp_hw_ipaddr.sin_addr, 3);
							NMP_DEBUG("set cpative portal socket option\n");
						}
#endif
	
						if(nvram_match("refresh_networkmap", "1")) {//reset client tables
							NMP_DEBUG("Reset client list!\n");
							lock = file_lock("networkmap");
							memset(p_client_detail_info_tab, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
#ifdef RTCONFIG_TAGGED_BASED_VLAN
							if(vlan_flag){
								for(i = 0; i < 8; i++){
									if(vlan_flag & (1<<i)){
										NMP_DEBUG("vlan %d reset\n", i);
										memset(vlan_client_detail_info_tab[i], 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
									}
								}
							}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
							if (fw_flag == 1){
								NMP_DEBUG("free-wifi shm reset\n");
								memset(fw_client_detail_info_tab, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
							}
							if (cp_flag == 1){
								NMP_DEBUG("captive portal shm reset\n");
								memset(cp_client_detail_info_tab, 0x00, sizeof(CLIENT_DETAIL_INFO_TABLE));
							}
#endif
							file_unlock(lock);
							nvram_unset("refresh_networkmap");
						}
						else {
							NMP_DEBUG("networkmap: refresh client list!\n");
							int x = 0;
							lock = file_lock("networkmap");
							for(; x < 255; x++){
								p_client_detail_info_tab->device_flag[x] &= (~(1<<FLAG_EXIST));
#ifdef RTCONFIG_TAGGED_BASED_VLAN
								if(vlan_flag){
									for(i = 0; i < 8; i++){
										if(vlan_flag & (1<<i)){
											vlan_client_detail_info_tab[i]->device_flag[x] &= (~(1<<FLAG_EXIST));
										}
									}
								}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
								if (fw_flag == 1)
									fw_client_detail_info_tab->device_flag[x] &= (~(1<<FLAG_EXIST));
								if (cp_flag == 1)
									cp_client_detail_info_tab->device_flag[x] &= (~(1<<FLAG_EXIST));
#endif
							}
							file_unlock(lock);
							NMP_DEBUG("refresh over\n");
						}
					}
					scan_count++;
					scan_ipaddr_he++;
					scan_ipaddr_ne = htonl(scan_ipaddr_he);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
					if(vlan_flag){
						for(i = 0; i < 8; i++){
							if(vlan_flag & (1<<i)){
								vlan_scan_ipaddr[i][3]++;
							}
						}
					}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
					if (fw_flag == 1)
						fw_scan_ipaddr[3]++;
					if (cp_flag == 1)
						cp_scan_ipaddr[3]++;
#endif
					if(scan_count < max_scan_count) {
						if(scan_ipaddr_he != my_ipaddr_he.s_addr)
							sent_arppacket(arp_sockfd, &my_ipaddr_ne, &scan_ipaddr_ne, dst_sockll);
						if(scan_count < 255) {
#ifdef RTCONFIG_TAGGED_BASED_VLAN
							if(vlan_flag){
								for(i = 0; i < 8; i++){
									if(vlan_flag & (1<<i)){
										if(memcmp(vlan_scan_ipaddr[i], vlan_ipaddr[i], 4))
											sent_arppacket(vlan_arp_sockfd[i], vlan_ipaddr[i], vlan_scan_ipaddr[i], vlan_dst_sockll[i]);
									}
								}
							}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
							if (fw_flag == 1)
								sent_arppacket(fw_arp_sockfd, fw_ipaddr, fw_scan_ipaddr, fw_dst_sockll);
							if (cp_flag == 1)
								sent_arppacket(cp_arp_sockfd, cp_ipaddr, cp_scan_ipaddr, cp_dst_sockll);
#endif
						}
					}	 
					else if(scan_count == max_scan_count) { //Scan completed
#if 0
						set_arp_timeout(arp_timeout, 0, 10000); //Reset timeout at monitor state for decase cpu loading
						setsockopt(arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
#ifdef RTCONFIG_TAGGED_BASED_VLAN
						if(vlan_flag){
							for(i = 0; i < 8; i++){
								if(vlan_flag & (1<<i)){
									setsockopt(vlan_arp_sockfd[i], SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
								}
							}
						}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
						if (fw_flag == 1)
							setsockopt(fw_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
						if (cp_flag == 1)
							setsockopt(cp_arp_sockfd, SOL_SOCKET, SO_RCVTIMEO, arp_timeout, sizeof(struct timeval));//set receive timeout
#endif
#endif
						networkmap_fullscan = 0;
						nvram_set("networkmap_fullscan", "0");
						NMP_DEBUG("Finish full scan!\n");
					}
				}// End of full scan

#if 0
				if( show_info )
				{	
					int ii = 0;
					NMP_DEBUG("\nIP / MAC / DevName / Apple Dev / Type / HTTP / Printer / iTune \n");
					while( ii < p_client_detail_info_tab->ip_mac_num)
					{

#if (defined(RTCONFIG_BWDPI) || defined(RTCONFIG_BWDPI_DEP))
						NMP_DEBUG(" %d.%d.%d.%d /%02X:%02X:%02X:%02X:%02X:%02X/%s/%s/%d/%d/%d/%d/%s/%s/%s/%s\n",
								p_client_detail_info_tab->ip_addr[ii][0],p_client_detail_info_tab->ip_addr[ii][1],
								p_client_detail_info_tab->ip_addr[ii][2],p_client_detail_info_tab->ip_addr[ii][3],
								p_client_detail_info_tab->mac_addr[ii][0],p_client_detail_info_tab->mac_addr[ii][1],
								p_client_detail_info_tab->mac_addr[ii][2],p_client_detail_info_tab->mac_addr[ii][3],
								p_client_detail_info_tab->mac_addr[ii][4],p_client_detail_info_tab->mac_addr[ii][5],
								p_client_detail_info_tab->device_name[ii],p_client_detail_info_tab->apple_model[ii],
								p_client_detail_info_tab->type[ii],
								(p_client_detail_info_tab->device_flag[ii] & (1<FLAG_HTTP))?1:0,
								(p_client_detail_info_tab->device_flag[ii] & (1<FLAG_PRINTER))?1:0,
								(p_client_detail_info_tab->device_flag[ii] & (1<FLAG_ITUNE))?1:0,
								p_client_detail_info_tab->bwdpi_host[ii],
								p_client_detail_info_tab->bwdpi_vendor[ii],
								p_client_detail_info_tab->bwdpi_type[ii],
								p_client_detail_info_tab->bwdpi_device[ii]
						);
#else
						NMP_DEBUG(" %d.%d.%d.%d /%02X:%02X:%02X:%02X:%02X:%02X/%s/%s/%d/%d/%d/%d\n",
								p_client_detail_info_tab->ip_addr[ii][0],p_client_detail_info_tab->ip_addr[ii][1],
								p_client_detail_info_tab->ip_addr[ii][2],p_client_detail_info_tab->ip_addr[ii][3],
								p_client_detail_info_tab->mac_addr[ii][0],p_client_detail_info_tab->mac_addr[ii][1],
								p_client_detail_info_tab->mac_addr[ii][2],p_client_detail_info_tab->mac_addr[ii][3],
								p_client_detail_info_tab->mac_addr[ii][4],p_client_detail_info_tab->mac_addr[ii][5],
								p_client_detail_info_tab->device_name[ii],p_client_detail_info_tab->apple_model[ii],
								p_client_detail_info_tab->type[ii],
								(p_client_detail_info_tab->device_flag[ii] & (1<FLAG_HTTP))?1:0,
								(p_client_detail_info_tab->device_flag[ii] & (1<FLAG_PRINTER))?1:0,
								(p_client_detail_info_tab->device_flag[ii] & (1<FLAG_ITUNE))?1:0
						      );
#endif
						ii++;
					}
					show_info = 0;
				}
#endif
				//arp buffer clean
				memset(buffer, 0, ARP_BUFFER_SIZE);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
				if(vlan_flag){
					for(i = 0; i < 8; i++){
						if(vlan_flag & (1<<i))
							memset(vlan_buffer[i], 0, ARP_BUFFER_SIZE);
					}
				}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
				if (fw_flag == 1)
					memset(fw_buffer, 0, ARP_BUFFER_SIZE);
				if (cp_flag == 1)
					memset(cp_buffer, 0, ARP_BUFFER_SIZE);
#endif
				//arp buffer clean end

				//receive arp packet
				arp_packet_rcv = 0;
				arp_getlen = recvfrom(arp_sockfd, buffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
				if(arp_getlen > 0)
					arp_packet_rcv = 1;
#ifdef RTCONFIG_TAGGED_BASED_VLAN
				if(vlan_flag){
					for(i = 0; i < 8; i++){
						if(vlan_flag & (1<<i)){
							vlan_arp_getlen[i] = recvfrom(vlan_arp_sockfd[i], vlan_buffer[i], ARP_BUFFER_SIZE, 0, NULL, NULL);
							if(vlan_arp_getlen[i] > 0)
								arp_packet_rcv = 1;
						}
					}
				}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
				if (fw_flag == 1){
					fw_arp_getlen = recvfrom(fw_arp_sockfd, fw_buffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
					if(fw_arp_getlen > 0)
						arp_packet_rcv = 1;
				}
				if (cp_flag == 1){
					cp_arp_getlen = recvfrom(cp_arp_sockfd, cp_buffer, ARP_BUFFER_SIZE, 0, NULL, NULL);
					if(cp_arp_getlen > 0)
						arp_packet_rcv = 1;
				}			
#endif
				//receive arp packet end

				if(arp_packet_rcv == 0) {
					if( scan_count < max_scan_count) {
						goto fullscan;
					}
					else
						break;
				}
				else {
					//protect memory overflow
					if(arp_getlen > 0){
						if(p_client_detail_info_tab->ip_mac_num >= max_scan_count) {
							refresh_sig(0);
							nvram_set("refresh_networkmap", "1");
							goto fullscan;
						}	
					}
#ifdef RTCONFIG_TAGGED_BASED_VLAN
					if(vlan_flag){
						for(i = 0; i < 8; i++){
							if(vlan_flag & (1<<i)){
								if(vlan_arp_getlen[i] > 0){
									if(vlan_client_detail_info_tab[i]->ip_mac_num >= 255) {
										refresh_sig(0);
										nvram_set("refresh_networkmap", "1");
										goto fullscan;
									}
								}
							}
						}
					}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
					if (fw_flag == 1){
						if(fw_arp_getlen > 0){
							if(fw_client_detail_info_tab->ip_mac_num >= 255) {
								refresh_sig(0);
								nvram_set("refresh_networkmap", "1");
								goto fullscan;
							}
						}
					}
					if (cp_flag == 1){
						if(cp_arp_getlen > 0){
							if(cp_client_detail_info_tab->ip_mac_num >= 255) {
								refresh_sig(0);
								nvram_set("refresh_networkmap", "1");
								goto fullscan;
							}
						}
					}
#endif
					//protect memory overflow end
					if(arp_getlen > 0)
						handle_client_list(p_client_detail_info_tab, buffer, &my_ipaddr_ne, scan_count);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
					if(vlan_flag){
						for(i = 0; i < 8; i++){
							if(vlan_flag & (1<<i)){
								if(vlan_arp_getlen[i] > 0){
									handle_client_list(vlan_client_detail_info_tab[i], 
											vlan_buffer[i], vlan_ipaddr[i], scan_count);
								}
							}
						}
					}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
					if (fw_flag == 1){
						if(fw_arp_getlen > 0)
							handle_client_list(fw_client_detail_info_tab, fw_buffer, fw_ipaddr, scan_count);
					}
					if (cp_flag == 1){
						if(cp_arp_getlen > 0)
							handle_client_list(cp_client_detail_info_tab, cp_buffer, cp_ipaddr, scan_count);
					}
#endif
				}//End of arp_getlen != -1
			//End of fullscan:
		} // End of while for flush buffer
#ifdef NMP_DB
		//Rawny: check delete signal
		if(delete_sig) {
			client_updated = DeletefromDB(p_client_detail_info_tab, nmp_cl_json);
			delete_sig = 0;
		}
#endif
		handle_detail_client_list(p_client_detail_info_tab);
#ifdef RTCONFIG_TAGGED_BASED_VLAN
		if(vlan_flag){
			for(i = 0; i < 8; i++){
				if(vlan_flag & (1<<i)){
					handle_detail_client_list(vlan_client_detail_info_tab[i]);
				}
			}
		}
#endif
#ifdef RTCONFIG_CAPTIVE_PORTAL
		if (fw_flag == 1)
			handle_detail_client_list(fw_client_detail_info_tab);
		if (cp_flag == 1)
			handle_detail_client_list(cp_client_detail_info_tab);
#endif
		if(nvram_match("nmp_wl_offline_check", "1"))	//web server trigger wl offline check
			nvram_unset("nmp_wl_offline_check");
	} //End of main while loop
	safe_leave(0);
	return 0;
}
