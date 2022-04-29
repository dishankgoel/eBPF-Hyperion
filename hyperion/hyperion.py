from bcc import BPF
from policies import Policy
import socket
import argparse


def insert_xdp_hook(policy):
    cflags = []
    bpf = BPF(src_file="ebpf/xdp_hook.c", cflags = [], debug=0)
    fn = bpf.load_func("hook", BPF.XDP)

    disallowed_ports = bpf[b"disallowed_ports"]
    disallowed_protocols = bpf[b"disallowed_protocols"]
    banned_ips = bpf[b"banned_ips"]
    for port in policy["disallowed_ports"]:
        disallowed_ports[disallowed_ports.Key(socket.htons(port))] = disallowed_ports.Leaf(True)
    # for




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
