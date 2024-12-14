#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

SEC("tc/ingress")
int tc_filter_src_ip(struct __sk_buff *skb) {
    // Get pointers to the beginning and end of the packet data
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK; // If we can't read the Ethernet header, pass the packet

    // Check if the packet is an IP packet
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK; // Not an IP packet, pass it

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK; // If we can't read the IP header, pass the packet

    // Check for a specific source IP (192.168.1.100)
    if (ip->saddr == __constant_htonl(0xc0a80164)) { // 192.168.1.100
        return TC_ACT_SHOT; // Drop the packet
    }

    return TC_ACT_OK; // Pass other packets
}

char _license[] SEC("license") = "GPL";