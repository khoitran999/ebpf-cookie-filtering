#ifndef __COMMON_H
#define __COMMON_H

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>
#include <bcc/helpers.h>  // Add this line
#include <linux/bpf.h>    // Add this line


#define MAX_HTTP_DATA 2048
#define MAX_COOKIE_DATA 1024

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u32 seq_num;
};

struct packet_info {
    __u32 src_ip;     
    __u32 dst_ip;     
    __u16 src_port;   
    __u16 dst_port;   
    __u8 protocol;    
    __u8 packet_type; 
    __u32 packet_len; 
    __u32 seq_num;    
    __u32 ack_num;    
    __u8 tcp_flags;   
    char http_data[MAX_HTTP_DATA];  
    __u32 http_data_len;
    char cookie_data[MAX_COOKIE_DATA];  
    __u32 cookie_len;
};

// Shared maps
BPF_HASH(xdp_tc_shared, struct flow_key, struct packet_info, 10000);
BPF_HASH(packet_count, __u32, __u64, 1024);
BPF_PERF_OUTPUT(cookie_events);
BPF_PERF_OUTPUT(packet_events);
BPF_PERCPU_ARRAY(tmp_packet, struct packet_info, 1);
BPF_PERCPU_ARRAY(sample_counter, __u64, 1);

#endif