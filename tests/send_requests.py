import threading
import requests
import socket

MESSAGE = "Hello, World!"

def send_req(ip):
    for i in range(10):
        r = requests.get(ip)
        print("ip: ", r.json)

# ip is of no use define udp ip above in globals
def send_udp_req(ip):
    for i in range(10):
        # print(i)
        sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
        sock.sendto(MESSAGE.encode(), (ip, 5005))

if __name__ == "__main__":
    t1 = threading.Thread(target=send_req, args=("http://172.17.0.3",))
    t2 = threading.Thread(target=send_req, args=("http://172.17.0.2",))
    t3 = threading.Thread(target=send_udp_req, args=("172.17.0.2",))

    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()

    print("Done!")
