#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>

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
};

// Hash map to count packets (up to 1024 unique keys)
BPF_HASH(packet_count, __u32, __u64, 1024);

// Per-CPU array for sampling counter
BPF_PERCPU_ARRAY(sample_counter, __u64, 1);

// Perf buffer to send packet details to userspace
BPF_PERF_OUTPUT(packet_events);

int count_tcp_packets(struct xdp_md *ctx) {
    // Data pointers
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Packet info structure (stack memory)
    struct packet_info info = {0};
    info.packet_len = data_end - data;

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
    info.src_ip = ip->saddr;
    info.dst_ip = ip->daddr;
    info.protocol = ip->protocol;

    // Handle TCP packets
    if (ip->protocol == IPPROTO_TCP) {
        // TCP header
        struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        info.src_port = bpf_ntohs(tcp->source);
        info.dst_port = bpf_ntohs(tcp->dest);
        info.packet_type = 0; // TCP

        // Extract TCP-specific fields
        info.seq_num = bpf_ntohl(tcp->seq);
        info.ack_num = bpf_ntohl(tcp->ack_seq);
        info.tcp_flags = ((tcp->fin & 0x1) | ((tcp->syn & 0x1) << 1) |
                          ((tcp->rst & 0x1) << 2) | ((tcp->psh & 0x1) << 3) |
                          ((tcp->ack & 0x1) << 4) | ((tcp->urg & 0x1) << 5));

        // Increment packet count for source IP
        __u64 *value = packet_count.lookup(&info.src_ip);
        if (value) {
            (*value)++;
        } else {
            __u64 initial_value = 1;
            packet_count.update(&info.src_ip, &initial_value);
        }

        // Sampling: Use per-CPU counter for consistency
        __u32 index = 0; // Index for the single entry in sample_counter
        __u64 *counter = sample_counter.lookup(&index);
        if (counter && ++(*counter) % 10 == 0) {
            // Log the first part of the TCP packet details
            bpf_trace_printk("TCP Packet: src_ip=%x, dst_ip=%x\n", info.src_ip, info.dst_ip);

            // Log the second part: ports
            bpf_trace_printk("src_port=%d, dst_port=%d\n", info.src_port, info.dst_port);

            // Log the third part: sequence and acknowledgment numbers
            bpf_trace_printk("seq=%u, ack=%u\n", info.seq_num, info.ack_num);

            // Log the fourth part: flags and length
            bpf_trace_printk("flags=0x%x, len=%d\n", info.tcp_flags, info.packet_len);

            // Send data to user space
            packet_events.perf_submit(ctx, &info, sizeof(info));
        }
    }

    return XDP_PASS;
}