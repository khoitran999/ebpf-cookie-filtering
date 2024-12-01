# Internal Code Documentation: HTTP Cookie Counter XDP Program

[TOC]

## 1. Introduction

This document provides internal documentation for the `count_http_cookies` eBPF XDP program. This program counts the number of packets associated with a specific attach cookie.  It leverages the `BPF_HASH` map for efficient counting.

## 2. Included Headers

The program includes the following header files:

| Header File             | Purpose                                                                     |
|--------------------------|-----------------------------------------------------------------------------|
| `<uapi/linux/bpf.h>`     | Provides eBPF core functionalities.                                           |
| `<uapi/linux/if_ether.h>` | Defines structures for Ethernet headers. (Not directly used in this example)|
| `<uapi/linux/ip.h>`      | Defines structures for IPv4 headers. (Not directly used in this example)     |
| `<uapi/linux/tcp.h>`     | Defines structures for TCP headers. (Not directly used in this example)    |
| `<uapi/linux/in.h>`      | Defines structures for internet addresses. (Not directly used in this example)|
| `<bcc/proto.h>`          | BCC helper functions (Not directly used in this example).                  |


## 3. Global Variables

The program uses a single global variable:

| Variable Name    | Type             | Purpose                                                                 |
|-----------------|-------------------|-------------------------------------------------------------------------|
| `cookie_count` | `BPF_HASH(__u64, __u64)` | A hash map to store the count of packets for each attach cookie. The key is the `__u64` cookie and the value is the `__u64` count. |


## 4. `count_http_cookies` Function

This function is the main entry point of the XDP program. It's triggered for every packet received.

**Function Signature:**

```c
int count_http_cookies(struct xdp_md *ctx)
```

**Parameters:**

* `ctx`: A pointer to the XDP metadata structure, providing access to the packet and its context.


**Algorithm:**

1. **Retrieve Attach Cookie:** The function first retrieves the attach cookie associated with the current packet using `bpf_get_attach_cookie(ctx)`. This cookie is a unique identifier provided during the program's attachment to the network interface.

2. **Increment Cookie Count:**  The core logic utilizes the `cookie_count` BPF hash map.
    * `cookie_count.lookup_or_init(&cookie, &zero)`: This attempts to find the entry for the given `cookie` in the map. If the entry exists, its address is stored in `value`. If it doesn't exist, a new entry is created with a value initialized to 0.
    * `__sync_fetch_and_add(value, 1)`: This atomically increments the count associated with the cookie.  The use of `__sync_fetch_and_add` ensures thread safety in a multi-core environment.

3. **Return XDP_PASS:** The function returns `XDP_PASS`, indicating that the packet should be processed further by the network stack.  This program only counts packets; it doesn't drop or modify them.


**Code Breakdown:**

```c
int count_http_cookies(struct xdp_md *ctx) {
    // Get the attach cookie directly from the context
    __u64 cookie = bpf_get_attach_cookie(ctx);

    // Increment the count for this specific attach cookie
    __u64 zero = 0, *value;
    value = cookie_count.lookup_or_init(&cookie, &zero);
    if (value) {
        __sync_fetch_and_add(value, 1);
    }

    return XDP_PASS;
}
```

## 5.  Error Handling

This program does not include explicit error handling. The `lookup_or_init` function handles the case where the cookie is not found in the map by creating a new entry.  The assumption is that memory allocation within the eBPF program will always succeed.  More robust error handling might be required in production deployments for situations like map overflow.

## 6. Conclusion

This XDP program provides a simple yet efficient mechanism for counting packets associated with specific attach cookies.  The use of the `BPF_HASH` map and atomic operations ensures performance and thread safety.  Further enhancements could include more sophisticated error handling and potentially expanding functionality to analyze packet content beyond the attach cookie.
