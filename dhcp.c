#include "dhcp.h"
#include "errno.h"

LIST_HEAD(dhcp_snooping_list);

DEFINE_SPINLOCK(slock);

struct task_struct* dhcp_thread = NULL;

void insert_dhcp_snooping_entry(u8 *mac, u32 ip, u32 lease_time, u32 expire_time) {
    struct dhcp_snooping_entry* entry;
    unsigned long flags;

    entry = kmalloc(sizeof(struct dhcp_snooping_entry), GFP_KERNEL);
    if (!entry) {
        printk(KERN_INFO "cybur: kmalloc failed\n");
        return;
    }
    entry->ip = ip;
    entry->lease_time = lease_time;
    entry->expires = expire_time;
    memcpy(entry->mac, mac, ETH_ALEN);
    
    spin_lock_irqsave(&slock, flags);
    list_add(&entry->list, &dhcp_snooping_list);
    spin_unlock_irqrestore(&slock, flags);
}


struct dhcp_snooping_entry* find_dhcp_snooping_entry(u32 ip) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry* entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &dhcp_snooping_list) {
        entry = list_entry(curr, struct dhcp_snooping_entry, list);
        if (entry->ip == ip) {
            spin_unlock_irqrestore(&slock, flags);
            return entry;
        }
    }
    spin_unlock_irqrestore(&slock, flags);
    return NULL;
}


void delete_dhcp_snooping_entry(u32 ip) {
    unsigned long flags;
    struct dhcp_snooping_entry* entry = find_dhcp_snooping_entry(ip);

    if (entry) {
        spin_lock_irqsave(&slock, flags);
        list_del(&entry->list);
        kfree(entry);
        spin_unlock_irqrestore(&slock, flags);
    }   
}


void clean_dhcp_snooping_table(void) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry* entry;
    unsigned long flags;

    spin_lock_irqsave(&slock, flags);
    list_for_each_safe(curr, next, &dhcp_snooping_list) {
        entry = list_entry(curr, struct dhcp_snooping_entry, list);
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock_irqrestore(&slock, flags);
}


int dhcp_thread_handler(void *arg) {
    struct list_head* curr, *next;
    struct dhcp_snooping_entry* entry;
    unsigned long flags;
    ktime_t current_time, entry_expiry_time;

    while (!kthread_should_stop()) {
        current_time = ktime_get();  // Get current time in nanoseconds

        spin_lock_irqsave(&slock, flags);
        list_for_each_safe(curr, next, &dhcp_snooping_list) {
            entry = list_entry(curr, struct dhcp_snooping_entry, list);
            entry_expiry_time = ktime_set(0, entry->expires * NSEC_PER_SEC);  // Convert expiry time to ktime_t

            if (ktime_compare(current_time, entry_expiry_time) >= 0) {
                printk(KERN_INFO "cybur:  %pI4 released at %lld\n", &entry->ip, ktime_to_ns(current_time));
                list_del(&entry->list);
                kfree(entry);
                spin_unlock_irqrestore(&slock, flags);
            }
        }
        msleep(1000);
    }
    return 0;
}


int dhcp_is_valid(struct sk_buff* skb) {
    int status = SUCCESS;
    struct udphdr* udp;
    struct dhcp* payload;
    struct ethhdr* eth;
    u8 dhcp_packet_type;
    unsigned char shaddr[ETH_ALEN];

    eth = eth_hdr(skb);
    memcpy(shaddr, eth->h_source, ETH_ALEN);

    udp = udp_hdr(skb);
    payload = (struct dhcp*) ((unsigned char*)udp + sizeof(struct udphdr));
    
    memcpy(&dhcp_packet_type, &payload->bp_options[2], 1);

    if ( dhcp_packet_type == DHCP_DISCOVER || dhcp_packet_type == DHCP_REQUEST) {
        if (memcmp(payload->chaddr, shaddr, ETH_ALEN) != 0) {
            printk(KERN_ERR "cybur:  the client MAC address %pM in the message body is NOT identical to the source MAC address in the Ethernet header %pM\n", payload->chaddr, shaddr);
            return -EHWADDR;
        }
    }
    
    if (payload->giaddr != 0) {
        printk(KERN_ERR "cybur:  GW ip address is not zero\n");
        return -EIPADDR;
    }
    
    return status;
}
