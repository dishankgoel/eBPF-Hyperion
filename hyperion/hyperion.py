from bcc import BPF
from policies import Policy
import socket
import argparse
import ipaddress
import ctypes as ct


def ip_strton(ip_address):
    addr = ipaddress.ip_address(ip_address)
    if addr.version == 4:
        return ct.c_uint(socket.htonl((int) (addr)))
    else:
        return (ct.c_ubyte * 16)(*list(addr.packed))


def insert_xdp_hook(policy):
    cflags = []
    bpf = BPF(src_file="ebpf/xdp_hook.c", cflags = [], debug=0)
    fn = bpf.load_func("hook", BPF.XDP)

    disallowed_ports = bpf[b"disallowed_ports"]
    banned_ips = bpf[b"banned_ips"]
    for port in policy["disallowed_ports"]:
        disallowed_ports[disallowed_ports.Key(socket.htons(port))] = disallowed_ports.Leaf(True)
    for banned_ip in policy["disallowed_ips"]:
        banned_ips[ip_strton(banned_ip)] = banned_ips.Leaf(True)
    bpf.attach_xdp("eth0", fn)


def run_monitor_sever():
    pass


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", "-p", help="Policy file")
    args = parser.parse_args()

    policy = Policy(args.policy)
    insert_xdp_hook(policy)
    run_monitor_sever()


if __name__ == "__main__":
    main()
