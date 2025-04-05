#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>

#define DEBUG 1
#define MAX_SEARCH 128  

struct event {
    char reason[64];
    __u32 src_ip;
    __u16 src_port;
    __u16 dest_port;
};

//struct {
 //   __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
 //   __uint(key_size, sizeof(int));
//    __uint(value_size, sizeof(__u32));
//} events SEC(".maps");

static const char *HTTP_SIGS[] = {
    "GET ", "POST ", "PUT ", 
    "HTTP/1.1", "HTTP/1.0",
    "Host: ", "\r\nContent-Length:"
};

static const int HTTP_SIG_LENS[] = {
    4, 5, 4, 
    8, 8,
    6, 16
};

struct tls_handshake {
    __u8 content_type; 
    __u16 version;     
    __u16 length;
    __u8 handshake_type;
};

static inline int memcmp_inline(const void *a, const void *b, int len) {
    const char *p1 = a;
    const char *p2 = b;
    for (int i = 0; i < len; i++) {
        if (p1[i] != p2[i])
            return 1;  // Non-zero means no match
    }
    return 0;  // Zero means match
}

SEC("xdp_fw")
int firewall(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    char *payload = (char *)(tcp + 1);
    int payload_len = data_end - (void *)payload;
    int search_depth = payload_len > MAX_SEARCH ? MAX_SEARCH : payload_len;
    
    for (int i = 0; i < sizeof(HTTP_SIGS)/sizeof(HTTP_SIGS[0]); i++) {
        int sig_len = HTTP_SIG_LENS[i];
        if (search_depth < sig_len) continue;
        
        for (int offset = 0; offset <= search_depth - sig_len; offset++) {
            if (memcmp_inline(payload + offset, HTTP_SIGS[i], sig_len) == 0) {
                if (DEBUG) bpf_printk("HTTP match: %s", HTTP_SIGS[i]);
                return XDP_PASS;
            }
        }
    }

    if (payload_len >= sizeof(struct tls_handshake)) {
        struct tls_handshake *tls = (struct tls_handshake *)payload;
        if (tls->content_type == 0x16 &&  
            bpf_ntohs(tls->version) >= 0x0301 &&
            tls->handshake_type == 0x01) {  
            if (DEBUG) bpf_printk("Valid TLS handshake");
            return XDP_PASS;
        }
    }

    // struct event ev = {
    //     .reason = "Blocked: Non HTTP/TLS",
    //     .src_ip = ip->saddr,
    //     .src_port = bpf_ntohs(tcp->source),
    //     .dest_port = bpf_ntohs(tcp->dest)
    // };
    // bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
