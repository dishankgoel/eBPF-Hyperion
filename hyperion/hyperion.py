from bcc import BPF
from config import Config
import socket
import argparse
import ipaddress
import ctypes as ct


def ip_strton(ip_address):
    addr = ipaddress.ip_address(ip_address)
    if addr.version == 4:
        return ct.c_uint(socket.htonl((int)(addr)))
    else:
        return (ct.c_ubyte * 16)(*list(addr.packed))

def mac_strton(mac_address):
    final_value = 0
    values = [int(i) for i in mac_address.split(':')]
    final_value |= (values[0] << (40 - 8*0))
    final_value |= (values[1] << (40 - 8*1))
    final_value |= (values[2] << (40 - 8*2))
    final_value |= (values[3] << (40 - 8*3))
    final_value |= (values[4] << (40 - 8*4))
    final_value |= (values[5] << (40 - 8*5))
    return final_value


def insert_xdp_hook(hconfig):
    cflags = []
    cflags.append("-DNUM_CONTAINERS={}".format(len(hconfig.containers)))
    cflags.append("-DLB_IP={}".format(ip_strton(hconfig.hyperion_container_ip)))
    cflags.append("-DLB_MAC={}".format(mac_strton(hconfig.hyperion_container_mac)))
    cflags.append("-DHOST_IP={}".format(ip_strton("172.17.0.1")))
    cflags.append("-DHOST_MAC={}".format(mac_strton("02:42:ca:5e:44:fc")))
    flags = 0
    bpf = BPF(src_file="ebpf/xdp_hook.c", cflags=cflags)
    device = "eth0"
    fn = bpf.load_func("hook", BPF.XDP)

    disallowed_ports = bpf[b"disallowed_ports"]
    banned_ips = bpf[b"banned_ips"]
    for port in hconfig.disallowed_ports:
        disallowed_ports[disallowed_ports.Key(
            socket.htons(port))] = disallowed_ports.Leaf(True)
    for banned_ip in hconfig.banned_ips:
        banned_ips[ip_strton(banned_ip)] = banned_ips.Leaf(True)

    # Add the container IPs and MACs to the container array
    containers = bpf[b"containers"]
    containers_mac = bpf[b"containers_mac"]
    i = 0
    for container_ip, container_mac in hconfig.containers:
        containers[ct.c_int(i)] = ip_strton(container_ip)
        containers_mac[ct.c_int(i)] = mac_strton(container_mac)
        i += 1

    bpf.attach_xdp(device, fn, flags)
    # print("Printing the trace")
    # try:
    #     bpf.trace_print()
    # except KeyboardInterrupt:
    #     print("Detaching XDP")
    bpf.remove_xdp(device, flags)


def run_monitor_sever():
    pass


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--config", "-c", help="Config file")
    args = parser.parse_args()

    myconfig = Config(args.config)
    insert_xdp_hook(myconfig)
    run_monitor_sever()


if __name__ == "__main__":
    main()
