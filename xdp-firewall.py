from bcc import BPF
import time

# Minimal XDP program
bpf_program = r"""
#include <uapi/linux/bpf.h>

int block_all(struct xdp_md *ctx) {
    return XDP_DROP;
}
"""

b = BPF(text=bpf_program)
fn = b.load_func("block_all", BPF.XDP)

# Attach to interface (change if needed)
INTERFACE = "enp0s1"
b.attach_xdp(INTERFACE, fn)

print(f"[+] XDP firewall attached to {INTERFACE}")
print("[!] All packets are now dropped")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[+] Detaching XDP program")
    b.remove_xdp(INTERFACE)

