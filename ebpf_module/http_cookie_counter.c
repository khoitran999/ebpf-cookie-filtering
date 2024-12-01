#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>
#include <bcc/proto.h>


BPF_HASH(cookie_count, __u64, __u64);

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
