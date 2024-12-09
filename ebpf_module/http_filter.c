#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>

#define MAX_HTTP_DATA 256
// Define a structure to hold detailed packet information
struct packet_info {
    __u32 src_ip;     // Source IP address
    __u32 dst_ip;     // Destination IP address
    __u16 src_port;   // Source port
    __u16 dst_port;   // Destination port
    __u8 protocol;    // IP protocol (TCP/UDP/ICMP etc)
    __u8 packet_type; // 0: TCP, 1: UDP, 2: ICMP, etc.
    __u32 packet_len; // Total packet length
    __u32 seq_num;    // Sequence number
    __u32 ack_num;    // Acknowledgment number
    __u8 tcp_flags;   // TCP flags
    char http_data[MAX_HTTP_DATA];  
    __u32 http_data_len;
};

// Hash map to count packets (up to 1024 unique keys)
BPF_HASH(packet_count, __u32, __u64, 1024);

// Per-CPU array for sampling counter
BPF_PERCPU_ARRAY(sample_counter, __u64, 1);

// Perf buffer to send packet details to userspace
BPF_PERF_OUTPUT(packet_events);

BPF_PERCPU_ARRAY(tmp_packet, struct packet_info, 1);


int count_tcp_packets(struct xdp_md *ctx) {
    // Data pointers
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Packet info structure (stack memory)
    int zero = 0;
    struct packet_info *info = tmp_packet.lookup(&zero);
    if (!info)
        return XDP_PASS;
    info->packet_len = data_end - data;

    // Ethernet header
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check if the packet is IP
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Populate IP details
    info->src_ip = ip->saddr;
    info->dst_ip = ip->daddr;
    info->protocol = ip->protocol;

    // Handle TCP packets
    if (ip->protocol == IPPROTO_TCP) {
        // TCP header
        struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        info->src_port = bpf_ntohs(tcp->source);
        info->dst_port = bpf_ntohs(tcp->dest);
        info->packet_type = 0; // TCP

        // Extract TCP-specific fields
        info->seq_num = bpf_ntohl(tcp->seq);
        info->ack_num = bpf_ntohl(tcp->ack_seq);
        info->tcp_flags = ((tcp->fin & 0x1) | ((tcp->syn & 0x1) << 1) |
                          ((tcp->rst & 0x1) << 2) | ((tcp->psh & 0x1) << 3) |
                          ((tcp->ack & 0x1) << 4) | ((tcp->urg & 0x1) << 5));

        // **ACK Packet Filtering**
        // Skip pure ACK packets (no SYN, FIN, PSH, RST, URG flags set)
        if (tcp->ack == 1 && tcp->syn == 0 && tcp->fin == 0 &&
            tcp->psh == 0 && tcp->rst == 0 && tcp->urg == 0) {
            return XDP_PASS;
        }

        // Increment packet count for source IP
        __u64 *value = packet_count.lookup(&info->src_ip);
        if (value) {
            (*value)++;
        } else {
            __u64 initial_value = 1;
            packet_count.update(&info->src_ip, &initial_value);
        }

        // Sampling: Use per-CPU counter for consistency
        __u32 index = 0; // Index for the single entry in sample_counter
        __u64 *counter = sample_counter.lookup(&index);
            // Log the first part of the TCP packet details

        void *http_data = (void *)tcp + (tcp->doff * 4);

        bpf_trace_printk("SRC IP1: %u",
            (info->src_ip));
        bpf_trace_printk("SRC IP2: %u.%u.%u",
            (info->src_ip & 0xFF),
            (info->src_ip >> 8) & 0xFF,
            (info->src_ip >> 16) & 0xFF);

        // Print source IP (last octet)
        bpf_trace_printk("SRC IP2: %u",
            (info->src_ip >> 24) & 0xFF,
            0, 0);  // Padding arguments

        // // Print destination IP (first two octets)
        // bpf_trace_printk("DST IP1: %u.%u.%u",
        //     (info->dst_ip & 0xFF),
        //     (info->dst_ip >> 8) & 0xFF,
        //     (info->dst_ip >> 16) & 0xFF);

        // // Print destination IP (last octet)
        // bpf_trace_printk("DST IP2: %u",
        //     (info->dst_ip >> 24) & 0xFF,
        //     0, 0);
        // // Log the second part: ports
        // bpf_trace_printk("src_port=%d, dst_port=%d\n", info->src_port, info->dst_port);

        // // Log the third part: sequence and acknowledgment numbers
        // bpf_trace_printk("seq=%u, ack=%u\n", info->seq_num, info->ack_num);

        // // Log the fourth part: flags and length
        // bpf_trace_printk("flags=0x%x, len=%d\n", info->tcp_flags, info->packet_len);
        // #pragma unroll
        // for (int i = 0; i < 1500; i += 3) {
        //     if (http_data + i + 2 > data_end)
        //         break;
                
        //     unsigned char *chunk = http_data + i;
        //     if (chunk + 2 <= (unsigned char *)data_end) {
        //         if (chunk >= (unsigned char *)data && 
        //             chunk + 2 < (unsigned char *)data_end) {
        //             bpf_trace_printk("HTTP: %c%c%c",
        //                 chunk[0],
        //                 chunk[1],
        //                 chunk[2]);
        //         }
        //     }
        // }
        // Send data to user space


if (http_data < data_end) {
    __u32 data_len = 0;
    // Safely compute the data length
    if (data_end > http_data) {
        
        data_len = data_end - http_data;
        bpf_trace_printk(" %d", data_len);

        if (data_len > MAX_HTTP_DATA)
            data_len = MAX_HTTP_DATA;
        
        if (data_len > 0) {
            // XDP programs can directly access packet data within bounds
            #pragma unroll
            for (int i = 0; i < MAX_HTTP_DATA; i++) {
                if (http_data + i >= data_end)
                    break;
                
                info->http_data[i] = *((char *)http_data + i);
            }
            
            info->http_data_len = data_len;
            packet_events.perf_submit(ctx, info, sizeof(*info));
        }
    }
}
    }

    return XDP_PASS;
}