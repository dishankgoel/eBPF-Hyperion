FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y software-properties-common python3-pip git
RUN add-apt-repository -y ppa:hadret/bpfcc && apt-get update && apt-get install -y bpfcc-tools linux-headers-$(uname -r) && apt install -y linux-tools-common linux-tools-generic linux-tools-$(uname -r) && pip3 install docker
RUN apt-get install -y vim net-tools curl

COPY . /eBPF-Hyperion

CMD ["/bin/bash"]
