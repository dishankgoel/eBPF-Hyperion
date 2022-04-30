FROM ubuntu:20.04

RUN apt-get update && apt-get install -y software-properties-common python3-pip git && add-apt-repository -y ppa:hadret/bpfcc && apt-get update && apt-get install bpfcc-tools linux-headers-$(uname -r) && apt install linux-tools-common linux-tools-generic linux-tools-$(uname -r)

COPY hyperion /hyperion

CMD ["/bin/bash"]
