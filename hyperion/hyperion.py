from bcc import BPF
from config import Config
import socket
import argparse
import ipaddress
import ctypes as ct
from fastapi import FastAPI, WebSocket
import time
import random

bpf = None

def ip_strton(ip_address):
    addr = ipaddress.ip_address(ip_address)
    if addr.version == 4:
        return ct.c_uint(socket.htonl((int)(addr)))
    else:
        return (ct.c_ubyte * 16)(*list(addr.packed))

def ip_ntostr(value):
    ip = socket.ntohl(value)
    # ip = "{}.{}.{}.{}".format((ip >> 3*8) & 0xff, (ip >> 2*8) & 0xff, (ip >> 1*8) & 0xff, (ip >> 0*8) & 0xff)
    return ip

def mac_strton(mac_address):
    final_value = 0
    values = [int(i, 16) for i in mac_address.split(':')]
    final_value |= (values[0] << (40 - 8*0))
    final_value |= (values[1] << (40 - 8*1))
    final_value |= (values[2] << (40 - 8*2))
    final_value |= (values[3] << (40 - 8*3))
    final_value |= (values[4] << (40 - 8*4))
    final_value |= (values[5] << (40 - 8*5))
    return ct.c_longlong(final_value)

device = "wlp3s0"
device = "docker0"

def insert_xdp_hook(hconfig):
    global bpf
    cflags = []
    # if(len(hconfig.containers) <= 1):
    #     print("No containers running to load balance")
    #     exit()
    # cflags.append("-DNUM_CONTAINERS={}".format(len(hconfig.containers)))
    # cflags.append("-DLB_IP={}".format(ip_strton(hconfig.hyperion_container_ip).value))
    # cflags.append("-DLB_MAC={}".format(mac_strton(hconfig.hyperion_container_mac).value))
    # cflags.append("-DHOST_IP={}".format(ip_strton("172.17.0.1").value))
    # cflags.append("-DHOST_MAC={}".format(mac_strton("02:42:ca:5e:44:fc").value))
    flags = 0
    bpf = BPF(src_file="ebpf/xdp_hook.c", cflags=cflags)

    disallowed_ports = bpf[b"disallowed_ports"]
    banned_ips = bpf[b"banned_ips"]
    for port in hconfig.disallowed_ports:
        disallowed_ports[disallowed_ports.Key(
            socket.htons(port))] = disallowed_ports.Leaf(True)
    for banned_ip in hconfig.banned_ips:
        banned_ips[ip_strton(banned_ip)] = banned_ips.Leaf(True)

    # Add the container IPs and MACs to the container array
    # containers = bpf[b"containers"]
    # containers_mac = bpf[b"containers_mac"]
    # i = 0
    # for container_ip, container_mac in hconfig.containers:
    #     containers[ct.c_int(i)] = ip_strton(container_ip)
    #     containers_mac[ct.c_int(i)] = mac_strton(container_mac)
    #     i += 1

    fn = bpf.load_func("hook", BPF.XDP)
    bpf.attach_xdp(device, fn, flags)
    # print("Printing the trace")
    # try:
    #     bpf.trace_print()
    # except KeyboardInterrupt:
    #     print("Detaching XDP")
    # bpf.remove_xdp(device, flags)

app = FastAPI()

@app.websocket('/ws')
async def websocket_endpoint(websocket: WebSocket):
    global bpf
    cnt = 0
    print("Accepting Connections")
    await websocket.accept()
    print("Accepted Connection")
    running = 1
    while running:
        time.sleep(1)
        cnt+=1
        try:
            # data = await websocket.receive_text()
            print("sending data")
            # await websocket.send_text(f"Sending from server! {cnt}")
            tcp_counter = bpf.get_table("tcp_counter")
            udp_counter = bpf.get_table("udp_counter")
            total_counter = bpf.get_table("total_counter")
            container_data = { }
            for k, v in tcp_counter.items():
                ip = ip_ntostr(k.value)
                # ip = k.value
                if ip in container_data:
                    container_data[ip]["tcp_counter"] = v.value
                else:
                    container_data[ip] = {"tcp_counter": v.value, "udp_counter": 0, "total_counter": 0}
            for k, v in udp_counter.items():
                ip = ip_ntostr(k.value)
                # ip = k.value
                if ip in container_data:
                    container_data[ip]["udp_counter"] = v.value
                else:
                    container_data[ip] = {"tcp_counter": 0, "udp_counter": v.value, "total_counter": 0}
            for k, v in total_counter.items():
                ip = ip_ntostr(k.value)
                # ip = k.value
                if ip in container_data:
                    container_data[ip]["total_counter"] = v.value
                else:
                    container_data[ip] = {"tcp_counter": 0, "udp_counter": 0, "total_counter": v.value}
            data = {}
            data["timestamp"] = time.perf_counter()
            data["cont_data"] = container_data
            print(data)
            await websocket.send_json(data)
            # print("[INFO] Data received: ", data)
        except Exception as e:
            print(f'[Error]: {e}')
            running = 0
            break

def main():
    import uvicorn
    myconfig = Config(None)
    # myconfig.disallowed_ports = [80]
    insert_xdp_hook(myconfig)

#     parser = argparse.ArgumentParser()
#     parser.add_argument("--config", "-c", help="Config file")
#     args = parser.parse_args()

    uvicorn.run(app, debug='true')
    print("SERVER ENDED")
    bpf.remove_xdp(device, 0)


if __name__ == "__main__":
    main()
