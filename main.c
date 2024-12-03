
#include "dhcp.h"
#include "errno.h"
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kedar Sathe, Aditya Sakhare");
MODULE_DESCRIPTION("cybur(Kernel Dynamic ARP Inspection) is a linux kernel module to defend against arp spoofing");
MODULE_VERSION("0.1");
#define eth_is_bcast(addr) (((addr)[0] & 0xffff) && ((addr)[2] & 0xffff) && ((addr)[4] & 0xffff))

static struct nf_hook_ops* arpho = NULL;
static struct nf_hook_ops* ipho = NULL;

static int arp_is_valid(struct sk_buff* skb, u16 ar_op, unsigned char* sha, 
                        u32 sip, unsigned char* tha, u32 tip);

static unsigned int arp_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct arphdr* arp;
    unsigned char* arp_ptr;
    unsigned char* sha, *tha;
    struct net_device* dev;
    struct in_device* indev;
    struct in_ifaddr* ifa;
    struct neighbour* hw;
    struct dhcp_snooping_entry* entry;
    unsigned int status = NF_ACCEPT;
    u32 sip, tip;
      
    if (unlikely(!skb))
        return NF_DROP;

    dev = skb->dev;
    indev = in_dev_get(dev);
    
    arp = arp_hdr(skb);
    arp_ptr = (unsigned char*)(arp + 1);
    sha	= arp_ptr;
    arp_ptr += dev->addr_len;
    memcpy(&sip, arp_ptr, 4);
    arp_ptr += 4;
    tha	= arp_ptr;
    arp_ptr += dev->addr_len;
    memcpy(&tip, arp_ptr, 4);

    printk(KERN_INFO "cybur :ARP packet receieved...on interface %s from %pM\n", ifa->ifa_label, sha);

    if (arp_is_valid(skb, ntohs(arp->ar_op), sha, sip, tha, tip) == 0) {
        for (ifa = indev->ifa_list; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_address == tip) {
                // querying arp table
                hw = neigh_lookup(&arp_tbl, &sip, dev);

                if (hw && memcmp(hw->ha, sha, dev->addr_len) != 0) {
                    status = NF_DROP;
                    printk(KERN_INFO "cybur: ARP spoofing detected on %s from IP %d.%d.%d.%d, MAC %pM\n using iptable",
                       ifa->ifa_label, NIPQUAD(sip), sha);
                    printk(KERN_INFO "cybur: Dropped packet");
                    neigh_release(hw);
                }
                // querying dhcp snooping table
                entry = find_dhcp_snooping_entry(sip);
                if (entry && memcmp(entry->mac, sha, ETH_ALEN) != 0) {
                    printk(KERN_INFO "cybur: ARP spoofing detected on %s from IP %d.%d.%d.%d, MAC %pM using DHCP\n",
                       ifa->ifa_label, NIPQUAD(sip), sha);
                    printk(KERN_INFO "cybur: Dropped packet");
                    status = NF_DROP;
                } else status = NF_ACCEPT;             
        
                break;
            } else status = NF_DROP; 
        }
   
    } else status = NF_DROP;
    
    return status;
}


static unsigned int ip_hook(void* priv, struct sk_buff* skb, const struct nf_hook_state* state) {
    struct udphdr* udp;
    struct dhcp* payload;
    unsigned char* opt;
    u8 dhcp_packet_type;
    u32 lease_time;
    ktime_t ts;
    struct dhcp_snooping_entry* entry;
    unsigned int status = NF_ACCEPT;

    if (unlikely(!skb))
        return NF_DROP;

    udp = udp_hdr(skb);

    

    if (udp->source == htons(DHCP_SERVER_PORT) || udp->source == htons(DHCP_CLIENT_PORT)) {
        payload = (struct dhcp*) ((unsigned char *)udp + sizeof(struct udphdr));

        if (dhcp_is_valid(skb) == 0) {
            memcpy(&dhcp_packet_type, &payload->bp_options[2], 1);

            switch (dhcp_packet_type) {

                // printk(KERN_INFO "cybur : IP packet with DHCP info received.");
                case DHCP_ACK: {
                    for (opt = payload->bp_options; *opt != DHCP_OPTION_END; opt += opt[1] + 2) {
                        if (*opt == DHCP_OPTION_LEASE_TIME) {
                            memcpy(&lease_time, &opt[2], 4);
                            break;
                        }
                    }
                    printk(KERN_INFO "cybur: DHCPACK of %pI4\n", &payload->yiaddr);
                    ts = ktime_get_real();
                    entry = find_dhcp_snooping_entry(payload->yiaddr);
                    if (entry) {
                        memcpy(entry->mac, payload->chaddr, ETH_ALEN);
                        entry->lease_time = ntohl(lease_time);
                        entry->expires = ktime_divns(ts, NSEC_PER_SEC) + ntohl(lease_time);
                    } else {
                        insert_dhcp_snooping_entry(
                            payload->chaddr, payload->yiaddr, ntohl(lease_time), 
                            ktime_divns(ts, NSEC_PER_SEC) + ntohl(lease_time));
                    }
                    break;
                }

                case DHCP_NAK: {
                    printk(KERN_INFO "cybur: DHCPNAK of %pI4\n", &payload->yiaddr);
                    entry = find_dhcp_snooping_entry(payload->yiaddr);
                    if (entry) {
                        delete_dhcp_snooping_entry(entry->ip);
                    }
                    break;
                }

                case DHCP_RELEASE: {
                    printk(KERN_INFO "cybur: DHCPRELEASE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr);
                    break;
                }

                case DHCP_DECLINE: {
                    printk(KERN_INFO "cybur: DHCPDECLINE of %pI4\n", &payload->ciaddr);
                    delete_dhcp_snooping_entry(payload->ciaddr);
                    break;
                }

                default:
                    break;
            }
      
        } else status = NF_DROP;
    }

    return status;
}



static int arp_is_valid(struct sk_buff* skb, u16 ar_op, unsigned char* sha, 
                                u32 sip, unsigned char* tha, u32 tip)  {
    int status = SUCCESS;
    const struct ethhdr* eth;
    unsigned char shaddr[ETH_ALEN],dhaddr[ETH_ALEN];

    eth = eth_hdr(skb);
    memcpy(shaddr, eth->h_source, ETH_ALEN);
    memcpy(dhaddr, eth->h_dest, ETH_ALEN);

    if (memcmp(sha, shaddr, ETH_ALEN) != 0) {
        printk(KERN_ERR "cybur: the sender MAC address %pM in the message body is NOT identical to the source MAC address in the Ethernet header %pM\n", sha, shaddr);
        return -EHWADDR;
    } 

    if (ipv4_is_multicast(sip)) {
        printk(KERN_ERR "cybur: the sender ip address %pI4 is multicast\n", &sip);
        return -EIPADDR;
    }

    if (ipv4_is_loopback(sip)) {
        printk(KERN_ERR "cybur: the sender ip address %pI4 is loopback\n", &sip);
        return -EIPADDR;
    }

    if (ipv4_is_zeronet(sip)) {
        printk(KERN_ERR "cybur: the sender ip address %pI4 is zeronet\n", &sip);
        return -EIPADDR;
    } 
            
    if (ipv4_is_multicast(tip)) {
        printk(KERN_ERR "cybur: the target ip address %pI4 is multicast\n", &tip);
        return -EIPADDR;
    }
            
    if (ipv4_is_loopback(tip)) {
        printk(KERN_ERR "cybur: the target ip address %pI4 is loopback\n", &tip);
        return -EIPADDR;
    }
            
    if (ipv4_is_zeronet(tip)) {
        printk(KERN_ERR "cybur: the target ip address %pI4 is zeronet\n", &tip);
        return -EIPADDR;
    }

    if (ar_op == ARPOP_REPLY) {
         if (memcmp(tha, dhaddr, ETH_ALEN) != 0) {
            printk(KERN_ERR "cybur: the target MAC address %pM in the message body is NOT identical" 
                            "to the destination MAC address in the Ethernet header %pM\n", tha, dhaddr);
            return -EHWADDR;
         }
    }
    return status;

}

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops *arpho;
static struct nf_hook_ops *ipho;

static int __init kdai_init(void) {
    /* Initialize arp netfilter hook */
    arpho = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (unlikely(!arpho))
        goto err;
    
    arpho->hook = arp_hook;
    arpho->hooknum = NF_ARP_IN;
    arpho->pf = NFPROTO_ARP;
    arpho->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, arpho);
    
    /* Initialize ip netfilter hook */
    ipho = (struct nf_hook_ops *) kcalloc(1, sizeof(struct nf_hook_ops), GFP_KERNEL);
    if (unlikely(!ipho))
        goto err;
    
    ipho->hook = ip_hook;
    ipho->hooknum = NF_INET_PRE_ROUTING;
    ipho->pf = NFPROTO_IPV4;
    ipho->priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, ipho);

    printk(KERN_INFO "cybur : started Kernel Module");
    
    return 0;   /* success */ 
    
err:
    if (arpho) kfree(arpho);
    if (ipho) kfree(ipho);
    return -ENOMEM;
}

static void __exit kdai_exit(void) {
    nf_unregister_net_hook(&init_net, arpho);
    nf_unregister_net_hook(&init_net, ipho);
    
    if (arpho) kfree(arpho);
    if (ipho) kfree(ipho);
}

module_init(kdai_init);
module_exit(kdai_exit);

