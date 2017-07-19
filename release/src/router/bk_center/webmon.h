#define IP_LEN                    32
#define MAC_LEN                   64
#define URL_LEN                256
#define DATE_LEN                  30
#define MAX_COUNT                 5000

typedef struct arp_info ARP_INFO;
struct arp_info
{
	char IP[IP_LEN];
	char MAC[MAC_LEN];
	ARP_INFO *next;
};
typedef struct device_info DEVICE_INFO;
struct device_info{
	char DATE[DATE_LEN];
	char IP[IP_LEN];
	char MAC[MAC_LEN];
	char URL[URL_LEN];
	DEVICE_INFO *next;
};

extern void webmon_usb_main(char *backup_path);
extern ARP_INFO *arp_arrange(void);
extern void arp_free_list(ARP_INFO *first);
extern void webmon_jffs_main(void);

