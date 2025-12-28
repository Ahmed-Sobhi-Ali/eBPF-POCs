from bcc import BPF
import ctypes
import signal
import sys

# ======================
# eBPF PROGRAM (C)
# ======================
bpf_program = r"""
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct packet_event {
    u64 ts;
    u32 ifindex;
    u32 pkt_len;
    u8  data[64];
};

BPF_RINGBUF_OUTPUT(events, 1024); 


int xdp_sniffer(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    u32 pkt_len = data_end - data;
    if (pkt_len < sizeof(struct ethhdr))
        return XDP_PASS;

    struct packet_event *e;
    e = events.ringbuf_reserve(sizeof(*e));
    if (!e)
        return XDP_PASS;

    e->ts = bpf_ktime_get_ns();
    e->ifindex = ctx->ingress_ifindex;
    e->pkt_len = pkt_len;

    u32 copy_len = pkt_len < 64 ? pkt_len : 64;
    bpf_probe_read_kernel(e->data, copy_len, data);

    events.ringbuf_submit(e, 0);
    return XDP_PASS;
}
"""

# ======================
# Python Struct (mirror)
# ======================
class PacketEvent(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_ulonglong),
        ("ifindex", ctypes.c_uint),
        ("pkt_len", ctypes.c_uint),
        ("data", ctypes.c_ubyte * 64),
    ]

# ======================
# Event handler
# ======================
def handle_event(cpu, data, size):
    event = ctypes.cast(data, ctypes.POINTER(PacketEvent)).contents
    raw = bytes(event.data)
    print(
        f"[IF={event.ifindex}] "
        f"len={event.pkt_len} "
        f"data={' '.join(f'{b:02x}' for b in raw)}"
    )

# ======================
# Load & attach XDP
# ======================
iface = "enp0s1" 

b = BPF(text=bpf_program)
fn = b.load_func("xdp_sniffer", BPF.XDP)

b.attach_xdp(dev=iface, fn=fn, flags=0)
print(f"[+] XDP sniffer attached on {iface}")

# ======================
# Ring buffer consumer
# ======================
b["events"].open_ring_buffer(handle_event)

def cleanup(sig, frame):
    print("\n[-] Detaching XDP...")
    b.remove_xdp(iface, flags=0)
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

# ======================
# Poll loop
# ======================
while True:
    b.ring_buffer_poll()
