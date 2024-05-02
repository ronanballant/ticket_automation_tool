import subprocess

from config import (destination_ip, destination_username, intel_processor_path,
                    jump_host_ip, jump_host_username, logger, private_key_path)


class IntelProcessor:
    def __init__(self, entities) -> None:
        self.entities = entities
        self.whitelist = []
        self.blocklist = []
        self.process_entities()
        self.process_whitelist("whitelist")
        self.process_blocklist("blocklist")

    def process_entities(self):
        for entity in self.entities:
            if entity.add_to_whitelist:
                self.whitelist.append(entity.domain)
                logger.info("{} added to the whitelist.".format(entity.domain))
            if entity.add_to_blocklist:
                self.blocklist.append(entity.domain)
                logger.info("{} added to the blocklist.".format(entity.domain))

    def process_whitelist(self):
        self.whitelist_string = ",".join(self.whitelist)

    def process_blocklist(self):
        self.blocklist_string = ",".join(self.blocklist)

    def send_entities_to_feed(self, operation):
        if self.whitelist:
            ssh_command = [
                "ssh",
                "-i",
                private_key_path,
                "-J {}@{}".format(jump_host_username, jump_host_ip),
                "{}@{}".format(destination_username, destination_ip),
                "python3 {} -o {} -d '{}'".format(
                    intel_processor_path, operation, self.whitelist_string
                ),
            ]

            try:
                # result = subprocess.run(ssh_command, check=True, capture_output=True, text=True)
                # logger.info(result.stdout)
                print("Send to whitelist: {}".format(self.whitelist))
            except subprocess.CalledProcessError as e:
                logger.error(f"ERROR Processing Whitelist Entities: {e}")

        if self.blocklist:
            ssh_command = [
                "ssh",
                "-i",
                private_key_path,
                "-J {}@{}".format(jump_host_username, jump_host_ip),
                "{}@{}".format(destination_username, destination_ip),
                "python3 {} -o {} -d '{}'".format(
                    intel_processor_path, operation, self.blocklist_string
                ),
            ]

            try:
                # result = subprocess.run(ssh_command, check=True, capture_output=True, text=True)
                # logger.info(result.stdout)
                print("Send to whitelist: {}".format(self.blocklist))
            except subprocess.CalledProcessError as e:
                logger.error(f"ERROR Processing Whitelist Entities: {e}")
