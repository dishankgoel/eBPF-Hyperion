import threading
import requests
import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
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
        sock.sendto(MESSAGE.encode(), (UDP_IP, UDP_PORT))

if __name__ == "__main__":
    t1 = threading.Thread(target=send_req, args=("http://www.google.com",))
    t2 = threading.Thread(target=send_req, args=("http://www.wikipedia.org",))
    t3 = threading.Thread(target=send_udp_req, args=("http://www.wikipedia.org",))

    # t1.start()
    # t2.start()
    t3.start()

    # t1.join()
    # t2.join()
    t3.join()

    print("Done!")