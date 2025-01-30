#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>    // This defines TC_ACT_OK
#include <bcc/helpers.h>



// Map to send cookie events to userspace
BCC_SEC("tc_cls")  // This places the function in the "tc_cls" section
int tc_cookie_filter(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    bpf_trace_printk("TC: Starting packet processing");

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void*)(ip + 1);
    if ((void*)(tcp + 1) > data_end)
        return TC_ACT_OK;

    struct flow_key key = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .src_port = bpf_ntohs(tcp->source),
        .dst_port = bpf_ntohs(tcp->dest),
        .seq_num = bpf_ntohl(tcp->seq)
    };
    // bpf_trace_printk("TC: Looking for packet with src_ip: %u", ip->saddr);
    // bpf_trace_printk("TC: Looking for packet with dst_ip: %u", ip->daddr);

    struct packet_info *pinfo = xdp_tc_shared.lookup(&key);
    if (!pinfo){
        bpf_trace_printk("TC: No packet info found in map");
        return TC_ACT_OK;
    }
    bpf_trace_printk("TC: Found packet info, http_data_len=%d", pinfo->http_data_len);


    __u32 offset = 0;
    bool copying = false;

    #pragma unroll
    for (int i = 500; i < 650; i++) {
        if (i >= pinfo->http_data_len)
            break;

        char c = pinfo->http_data[i];
        bpf_trace_printk("%c", c);  // Print position and character
        if (!copying) {
            if (i + 3 < pinfo->http_data_len && 
                c == 'S' && 
                pinfo->http_data[i+1] == 'e' && 
                pinfo->http_data[i+2] == 't') {
                copying = true;
                i += 3;  // Skip to after "Set"
                continue;
            }
        } else {
            if (offset >= MAX_COOKIE_DATA - 1 || c == '\n')
                break;
                
            pinfo->cookie_data[offset++] = c;
        }
    }


        pinfo->cookie_len = offset;
        cookie_events.perf_submit(skb, pinfo, sizeof(*pinfo));
    

    xdp_tc_shared.delete(&key);
    return TC_ACT_OK;
}