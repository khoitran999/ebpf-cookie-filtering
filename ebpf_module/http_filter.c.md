# Internal Code Documentation: eBPF Packet Counter and Sampler

## Table of Contents

1. [Introduction](#introduction)
2. [Data Structures](#data-structures)
    * [struct packet_info](#struct-packet_info)
3. [BPF Maps and Arrays](#bpf-maps-and-arrays)
    * [packet_count](#packet_count)
    * [sample_counter](#sample_counter)
4. [BPF Perf Buffer](#bpf-perf-buffer)
    * [packet_events](#packet_events)
5. [Core Function: count_tcp_packets](#core-function-count_tcp_packets)
    * [Packet Processing Pipeline](#packet-processing-pipeline)
    * [TCP Packet Handling](#tcp-packet-handling)
    * [Packet Counting](#packet-counting)
    * [Sampling and Logging](#sampling-and-logging)
6. [Conclusion](#conclusion)


## <a name="introduction"></a>1. Introduction

This document details the implementation of an eBPF program designed to count TCP packets and sample TCP packet information for analysis.  The program processes packets in the XDP (eXpress Data Path) context, allowing for high-performance packet inspection without copying data to kernel space. The program focuses on TCP packets but the structure is designed to accommodate other protocols in the future.

## <a name="data-structures"></a>2. Data Structures

### <a name="struct-packet_info"></a>struct packet_info

| Field Name    | Type       | Description                                  |
|---------------|------------|----------------------------------------------|
| `src_ip`      | `__u32`    | Source IP address.                           |
| `dst_ip`      | `__u32`    | Destination IP address.                        |
| `src_port`    | `__u16`    | Source port.                                 |
| `dst_port`    | `__u16`    | Destination port.                             |
| `protocol`    | `__u8`     | IP protocol (e.g., IPPROTO_TCP, IPPROTO_UDP). |
| `packet_type` | `__u8`     | Packet type (0: TCP, 1: UDP, 2: ICMP, etc.). |
| `packet_len`  | `__u32`    | Total packet length.                         |
| `seq_num`     | `__u32`    | TCP sequence number.                          |
| `ack_num`     | `__u32`    | TCP acknowledgment number.                    |
| `tcp_flags`   | `__u8`     | TCP flags (FIN, SYN, RST, PSH, ACK, URG).     |


## <a name="bpf-maps-and-arrays"></a>3. BPF Maps and Arrays

### <a name="packet_count"></a>packet_count

A `BPF_HASH` map that stores the count of packets for each source IP address.  It uses the source IP address (`__u32`) as the key and a 64-bit unsigned integer (`__u64`) as the value (packet count). The map is sized to hold up to 1024 unique keys.

### <a name="sample_counter"></a>sample_counter

A `BPF_PERCPU_ARRAY` that acts as a per-CPU sampling counter. It has a single entry (`__u64`) to ensure atomic increment operations without race conditions across multiple CPUs.

## <a name="bpf-perf-buffer"></a>4. BPF Perf Buffer

### <a name="packet_events"></a>packet_events

A `BPF_PERF_OUTPUT` structure used to send detailed packet information (`struct packet_info`) to userspace for further processing and analysis.


## <a name="core-function-count_tcp_packets"></a>5. Core Function: count_tcp_packets

The `count_tcp_packets` function is the core of the eBPF program. It's triggered for each packet received.

### <a name="packet-processing-pipeline"></a>Packet Processing Pipeline

1. **Data Pointers:**  The function retrieves pointers to the beginning and end of the packet data from the `xdp_md` context.
2. **Packet Length:** The total packet length is calculated.
3. **Ethernet Header Check:** It validates that the packet has an Ethernet header and checks if the protocol is IP (`ETH_P_IP`). If not, it returns `XDP_PASS`, passing the packet to the next processing stage.
4. **IP Header Processing:** It extracts source and destination IP addresses, and the IP protocol from the IP header.
5. **TCP Packet Handling:** If the protocol is TCP (`IPPROTO_TCP`), it processes the TCP header.
6. **TCP Header Extraction:** It extracts the TCP source and destination ports, sequence number, acknowledgment number, and flags.
7. **Packet Counting and Sampling:** It then increments the packet count for the source IP address and implements sampling logic using the `sample_counter`.

### <a name="tcp-packet-handling"></a>TCP Packet Handling

The function specifically handles TCP packets by extracting relevant fields from the TCP header.  The TCP flags are combined into a single byte for efficient storage.

### <a name="packet-counting"></a>Packet Counting

The `packet_count` BPF hash map is used to maintain a count of packets originating from each unique source IP address.  If a source IP is not already in the map, a new entry is created with a count of 1. Otherwise, the existing count is incremented.

### <a name="sampling-and-logging"></a>Sampling and Logging

The sampling mechanism uses the per-CPU `sample_counter`.  Every 10th packet, the following actions occur:

1. **Logging:**  Partial TCP packet information (source IP, destination IP, source port, destination port, sequence number, acknowledgment number, TCP flags, and packet length) is logged using `bpf_trace_printk`. The logging is split into multiple `bpf_trace_printk` calls to avoid exceeding the maximum trace message size.

2. **Perf Event Submission:**  A complete `struct packet_info` is sent to userspace via the `packet_events` perf buffer. This allows for more detailed analysis of the sampled packets.

## <a name="conclusion"></a>6. Conclusion

This eBPF program provides a robust and efficient mechanism for counting and sampling TCP packets. The use of BPF maps, arrays and perf buffers optimizes performance and allows for detailed analysis of network traffic without significant overhead. The sampling mechanism ensures that resource usage remains manageable while still providing useful insights.
