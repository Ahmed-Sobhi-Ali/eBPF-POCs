# eBPF Proof of Concepts (POCs)

A collection of educational eBPF/XDP programs for network packet inspection and manipulation at kernel level.


## Overview

This repository contains eBPF/XDP programs designed for:

- Educational purposes and learning eBPF/XDP
- Network packet inspection and analysis
- Understanding kernel-level packet processing
- Testing eBPF program behavior in controlled environments

## Prerequisites

### System Requirements

- **Linux kernel 4.8+** (XDP support required)
- **Root/sudo access** (for loading eBPF programs)
- **GCC or Clang compiler** (Clang 3.7.1+ recommended)
- **libbpf development libraries**
- **BPF filesystem mounted**

### Kernel Configuration

Ensure your kernel has BPF support enabled:

```bash
# Check BPF support
grep -i bpf /boot/config-$(uname -r)

# Check XDP support
grep -i xdp /boot/config-$(uname -r)
```

## Installation

### Install Dependencies

#### Ubuntu/Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-tools-common \
    linux-tools-$(uname -r)
```

#### RHEL/CentOS/Fedora

```bash
# RHEL/CentOS 8+
sudo yum install -y \
    clang \
    llvm \
    elfutils-libelf-devel \
    libbpf-devel \
    kernel-devel-$(uname -r)

# Fedora
sudo dnf install -y \
    clang \
    llvm \
    elfutils-libelf-devel \
    libbpf-devel \
    kernel-devel
```

#### Arch Linux

```bash
sudo pacman -S --needed \
    base-devel \
    clang \
    llvm \
    libelf \
    linux-headers
```


## Getting Started

### Clone the Repository

```bash
git clone https://github.com/Ahmed-Sobhi-Ali/eBPF-POCs.git
cd eBPF-POCs
```


### Manual Compilation

```bash
# Compile eBPF program with debug info
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
      -I/usr/include/$(uname -m)-linux-gnu \
      -c src/xdp_packet_dump.c \
      -o build/xdp_packet_dump.o

# Alternative: Use pkg-config for library paths
clang -O2 -g -target bpf -c src/xdp_packet_dump.c \
      $(pkg-config --cflags libbpf) \
      -o build/xdp_packet_dump.o
```

### Loading Methods

#### Method 1: Using iproute2 (Recommended)

```bash
# Load with generic mode (driver-agnostic)
sudo ip link set dev eth0 xdp obj build/xdp_packet_dump.o sec xdp

# Load with native mode (requires driver support)
sudo ip link set dev eth0 xdp obj build/xdp_packet_dump.o sec xdp verb

# Load with offload mode (hardware acceleration)
sudo ip link set dev eth0 xdpoffload obj build/xdp_packet_dump.o sec xdp
```

#### Method 2: Using bpftool

```bash
# Load program
sudo bpftool prog load build/xdp_packet_dump.o /sys/fs/bpf/xdp_dump

# Attach to interface
sudo bpftool net attach xdp pinned /sys/fs/bpf/xdp_dump dev eth0
```

### Verify Program Status

```bash
# Check interface XDP status
ip link show eth0
# Look for: "xdp" in output

# List loaded BPF programs
sudo bpftool prog show

# Show program details
sudo bpftool prog show id <PROG_ID> --pretty

# List XDP attachments
sudo bpftool net show
```

## Output Examples

### Real-time Monitoring

```bash
# Continuous monitoring
sudo cat /sys/kernel/debug/tracing/trace_pipe

# Filtered monitoring
sudo ./scripts/monitor.sh | grep -E "TCP|UDP|ICMP"
```

### Sample Output Format

```
[IF=2] len=1506 data=1e 07 6d c0 a2 76 08 00 45 00 05 dc 00 00 40 00 ...
[IF=2] len=64 data=ff ff ff ff ff ff 00 0c 29 2d 4c 9f 08 06 00 01 ...
[IF=2] len=342 data=00 0c 29 2d 4c 9f 1e 07 6d c0 a2 76 08 00 45 00 ...
```

### Understanding Output

- `IF=2` - Interface index (map to interface name with `ip link`)
- `len=1506` - Total packet length in bytes
- `data=...` - First 64 bytes of packet in hex format


## Technical Notes

### Packet Copy Limitation

The program copies only the first 64 bytes of each packet:

```c
u32 copy_len = pkt_len < 64 ? pkt_len : 64;
```

**Design Rationale:**

1. **Performance** - Reduces CPU overhead and memory access
2. **Verifier Compatibility** - Stays within complexity limits
3. **Practicality** - Most protocol headers fit within 64 bytes
4. **Safety** - Avoids accessing out-of-bounds packet data

### XDP Return Codes

The program currently returns `XDP_PASS`. Available alternatives:

| Return Code | Description | Use Case |
|-------------|-------------|----------|
| `XDP_PASS` | Allow packet to continue | Monitoring, analysis |
| `XDP_DROP` | Discard packet immediately | Firewalling, rate limiting |
| `XDP_ABORTED` | Error occurred, drop with trace | Debugging, error handling |
| `XDP_REDIRECT` | Redirect to another interface | Load balancing, tunneling |
| `XDP_TX` | Transmit back on same interface | Reflection, hairpinning |

### Performance Considerations

#### Adjust Copy Size

```c
// For full packet capture (use with caution)
u32 copy_len = pkt_len;

// For headers only (common case)
u32 copy_len = pkt_len < 128 ? pkt_len : 128;
```

#### Add Sampling Rate

```c
// Sample 1 in 100 packets
if (bpf_get_prandom_u32() % 100 != 0)
    return XDP_PASS;
```

#### Minimize Map Operations

Minimize map operations in fast path to maintain performance.

## Security Warning

### Critical Considerations

**THIS SOFTWARE OPERATES AT KERNEL LEVEL AND CAN:**

1. Bypass all security mechanisms (firewalls, iptables, etc.)
2. Cause complete network disruption if misconfigured
3. Introduce kernel vulnerabilities if programs contain bugs
4. Be difficult to diagnose when causing issues

### Safety Guidelines

**Test Environment Requirements:**

- Use virtual machines or isolated test hardware
- Have physical/console access to test machines
- Test on non-production interfaces first
- Keep backup network configuration
- Test during maintenance windows

**Production Usage (if absolutely necessary):**

- Complete code review by eBPF experts
- Extensive testing in staging environment
- Implement fallback mechanisms
- Monitor system metrics closely
- Have rollback procedures ready

### Emergency Recovery

If network connectivity is lost:

```bash
# 1. Unload all XDP programs
sudo ip link set dev eth0 xdp off

# 2. Remove BPF programs
sudo rm -rf /sys/fs/bpf/*

# 3. Reboot if necessary
sudo reboot
```

