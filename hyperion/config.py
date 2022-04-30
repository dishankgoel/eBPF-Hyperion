import json
import docker


class Config:

    def __init__(self, config_file) -> None:
        self.config_file = config_file
        self.docker = docker.from_env()
        self.disallowed_ports = []
        self.banned_ips = []
        self.hyperion_container_ip, self.hyperion_container_mac = self.get_hyperion_container()
        self.containers = []
        self.parse_config()

    def parse_config(self):
        if self.config_file is not None:
            with open(self.config_file) as f:
                config_json = json.load(f)
            if "containers" in config_json:
                config_json["containers"] = self.ip_from_containers(config_json["containers"])
            else:
                config_json["containers"] = self.ip_all_containers()
        else:
            config_json = {
                "disallowed_ports": [],
                "banned_ips": [],
                "containers": self.ip_all_containers()
            }
        self.disallowed_ports = config_json['disallowed_ports']
        self.banned_ips = config_json['banned_ips']

    def get_hyperion_container(self):
        try:
            c = self.docker.containers.get("hyperion")
            return (c.attrs['NetworkSettings']['IPAddress'], c.attrs['NetworkSettings']['MacAddress'])
        except Exception:
            print("Hyperion container does not exist")
            exit()

    def ip_from_containers(self, containers):
        ips = []
        for container_id in containers:
            try:
                container = self.docker.containers.get(container_id)
            except Exception:
                print("{} container does not exist".format(container_id))
                exit(0)
            ip = container.attrs["NetworkSettings"]['IPAddress']
            mac = container.attrs["NetworkSettings"]['MacAddress']
            if ip != self.hyperion_container_ip:
                ips.append((ip, mac))
        return ips


    def ip_all_containers(self):
        containers = self.docker.containers.list()
        all_ips = []
        for container in containers:
            ip = container.attrs["NetworkSettings"]['IPAddress']
            mac = container.attrs["NetworkSettings"]['MacAddress']
            if ip != self.hyperion_container_ip:
                all_ips.append((ip, mac))
        return all_ips
