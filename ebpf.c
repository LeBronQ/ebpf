#include <linux/bpf.h>
#include <linux/pkt_cls.h>

struct bpf_map_def SEC("maps") loss_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(u32),
    .value_size  = sizeof(u32),
    .max_entries = 1,
};

SEC("tc")
int tc_drop(struct __sk_buff *skb)
{
    // 从map中获取丢包率
    u32 *loss_rate = bpf_map_lookup_elem(&loss_map, 0);
    if (!loss_rate) {
        return TC_ACT_OK;
    }

    // 根据丢包率随机丢弃数据包
    if (skb->hash % 100 < *loss_rate) {
        bpf_trace_printk("Dropping packet\n");
        return TC_ACT_SHOT;
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

