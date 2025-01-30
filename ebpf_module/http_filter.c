#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include <bcc/helpers.h>

BCC_SEC("xdp")
int count_tcp_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    int zero = 0;
    struct packet_info *info = tmp_packet.lookup(&zero);
    if (!info)
        return XDP_PASS;
    info->packet_len = data_end - data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    info->src_ip = ip->saddr;
    info->dst_ip = ip->daddr;
    info->protocol = ip->protocol;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        info->src_port = bpf_ntohs(tcp->source);
        info->dst_port = bpf_ntohs(tcp->dest);
        info->packet_type = 0;
        info->seq_num = bpf_ntohl(tcp->seq);
        info->ack_num = bpf_ntohl(tcp->ack_seq);
        info->tcp_flags = ((tcp->fin & 0x1) | ((tcp->syn & 0x1) << 1) |
                          ((tcp->rst & 0x1) << 2) | ((tcp->psh & 0x1) << 3) |
                          ((tcp->ack & 0x1) << 4) | ((tcp->urg & 0x1) << 5));



        void *http_data = (void *)tcp + (tcp->doff * 4);

        if (tcp->ack == 1 && tcp->syn == 0 && tcp->fin == 0 &&
            tcp->psh == 0 && tcp->rst == 0 && tcp->urg == 0 &&
            data_end - http_data == 0) {
            return XDP_PASS;
        }

        __u64 *value = packet_count.lookup(&info->src_ip);
        if (value) {
            (*value)++;
        } else {
            __u64 initial_value = 1;
            packet_count.update(&info->src_ip, &initial_value);
        }

        if (http_data < data_end) {
            __u32 data_len = data_end - http_data;
            if (data_len > MAX_HTTP_DATA)
                data_len = MAX_HTTP_DATA;

            if (data_len > 0) {
                #pragma unroll
                for (int i = 0; i < MAX_HTTP_DATA; i++) {
                    if (http_data + i >= data_end)
                        break;
                    info->http_data[i] = *((char *)http_data + i);
                }
                
                info->http_data_len = data_len;


                // Only process HTTP/HTTPS responses
                if (info->src_port == 80 || info->src_port == 443 ||
                    info->dst_port == 80 || info->dst_port == 443) {
                    struct flow_key key = {
                        .src_ip = info->src_ip,
                        .dst_ip = info->dst_ip,
                        .src_port = info->src_port,
                        .dst_port = info->dst_port,
                        .seq_num = info->seq_num
                    };
                    bpf_trace_printk("XDP: Found HTTP packet from port %d", info->src_port);
                    bpf_trace_printk("XDP: Processing packet src_ip: %u, port: %d", info->src_ip, info->src_port);

                    packet_events.perf_submit(ctx, info, sizeof(*info));
                    int ret = xdp_tc_shared.update(&key, info);
                    if (ret == 0) {
                        bpf_trace_printk("XDP: Successfully updated shared map");
                    } else {
                        bpf_trace_printk("XDP: Failed to update shared map");
                    }                
                }
            }
        }
    }

    return XDP_PASS;
}

