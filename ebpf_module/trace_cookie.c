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


// Perf buffer to send packet details to userspace
BPF_PERF_OUTPUT(packet_events);

BPF_PERCPU_ARRAY(tmp_packet, struct packet_info, 1); //array of 1 element containing packet_info


int trace_cookie(struct xdp_md *ctx) {
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
        void *http_data = (void *)tcp + (tcp->doff * 4);

        // **ACK Packet Filtering**
        // Skip pure ACK packets (no SYN, FIN, PSH, RST, URG flags set)
        if (tcp->ack == 1 && tcp->syn == 0 && tcp->fin == 0 &&
            tcp->psh == 0 && tcp->rst == 0 && tcp->urg == 0 &&
            data_end - http_data == 0) {
            return XDP_PASS;
        }
        
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


        // if (data_end > http_data) {
        //     #pragma unroll
        //     for (int i = 0; i < payload_len - COOKIE_KEY_LEN; i++) {
        //         if ((void *)(http_data + i + COOKIE_KEY_LEN) > data_end)
        //             break;

        //         // Match "Cookie: "
        //         if (__builtin_memcmp(http_data + i, COOKIE_KEY, COOKIE_KEY_LEN) == 0) {
        //             int cookie_offset = i + COOKIE_KEY_LEN;
        //             int j;
        //             for (j = 0; j < MAX_HTTP_DATA - 1 && (cookie_offset + j) < payload_len; j++) {
        //                 if (http_data[cookie_offset + j] == '\n' || http_data[cookie_offset + j] == '\r')
        //                     break; // Stop at newline
        //                 info->cookie[j] = http_data[cookie_offset + j];
        //             }
        //             info->cookie[j] = '\0'; // Null-terminate
        //             break;
        //         }
        //     }
            
        // //     __u32 data_len = data_end - http_data;
        // //     // bpf_trace_printk(" %d", data_len);

        // //     if (data_len > MAX_HTTP_DATA)
        // //         data_len = MAX_HTTP_DATA;
            

        // //     // XDP programs can directly access packet data within bounds
        // //     #pragma unroll
        // //     for (int i = 0; i < data_len; i++) {
                
        // //         info->http_data[i] = *((char *)http_data + i);
        // //     }
            
        // //     info->http_data_len = data_len;
        //     packet_events.perf_submit(ctx, info, sizeof(*info));
            
            
        // }
    }


    return XDP_PASS;
}


