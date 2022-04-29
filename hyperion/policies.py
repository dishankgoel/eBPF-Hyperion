import json

class Policy:

    def __init__(self, policy_file) -> None:
        self.policy_file = policy_file
        self.disallowed_ports = []
        self.banned_ips = []
        self.parse_policy()

    def parse_policy(self):
        if self.policy_file is not None:
            with open(self.policy_file) as f:
                policy_json = json.load(f)
        else:
            policy_json = {"disallowed_ports": [], "banned_ips": []}
        self.disallowed_ports = policy_json['disallowed_ports']
        self.banned_ips = policy_json['banned_ips']
