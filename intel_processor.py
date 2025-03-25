import fileinput
import csv
from config import (destination_ip, destination_username, 
                    intel_processor_path, jump_host_ip, jump_host_username, private_key_path,
                    destination_intel_file_path, whitelist_file, blacklist_file, secops_feed_file, sps_intel_update_file)
from typing import List
import subprocess


class IntelProcessor:
    def __init__(self, logger, intel_entries) -> None:
        self.logger = logger
        self.intel_entries = intel_entries
        self.whitelist: List[str] = []
        self.whitelist_removal: List[str] = []
        self.blacklist: List[str] = []
        self.manual_blacklist: List[str] = []
        self.data_strings: List[str] = []
        self.add_error_comment: bool = False
        self.error_comment: str = ""

    def process_indicators(self):
        for intel_entry in self.intel_entries:
            if intel_entry.is_approved is True:
                self.update_indicator(intel_entry)
                if intel_entry.is_valid_update is True:
                    if intel_entry.intel_list.lower() == "whitelist":
                        if intel_entry.operation.lower() == "add":
                            self.whitelist.append(intel_entry.approved_intel_change)
                            self.logger.info(f"{intel_entry.indicator.fqdn} identified for the allow list.")
                        elif intel_entry.operation.lower() == "remove":
                            self.whitelist_removal.append(intel_entry.approved_intel_change)
                            self.logger.info(f"{intel_entry.indicator.fqdn} identified for whitelist removal.")
                    elif intel_entry.intel_list.lower() == "blacklist":
                        if intel_entry.operation.lower() == "add":
                            self.blacklist.append(intel_entry.approved_intel_change)
                            self.logger.info(f"{intel_entry.indicator.fqdn} identified for the block list.")
                        elif intel_entry.operation.lower() == "remove":
                            self.manual_blacklist.append(intel_entry.approved_intel_change)
                            self.logger.info(f"{intel_entry.indicator.fqdn} identified for manual blacklist removal.")

        self.whitelist = list(set(self.whitelist))
        self.blacklist = list(set(self.blacklist))
        self.manual_blacklist = list(set(self.manual_blacklist))
    
    def add_to_etp_whitelist(self):
        if self.whitelist:
            self.logger.info("Adding to manual whitelist")
            with open(whitelist_file, "a", newline="") as file:
                writer = csv.writer(file, lineterminator="\n")
                for intel_entry in self.whitelist:
                    self.logger.info(f"Adding {intel_entry} to {whitelist_file}")
                    entry = [x.strip() for x in intel_entry.strip().split(",")]
                    writer.writerow(entry)
        else:
            self.logger.info("No additions for manual whitelist")

    def add_to_etp_blacklist(self):
        if self.blacklist:
            self.logger.info("Adding to SecOps Feed")
            with open(secops_feed_file, "a", newline="") as file:
                writer = csv.writer(file, lineterminator="\n")
                for intel_entry in self.blacklist:
                    self.logger.info(f"Adding {intel_entry} to {secops_feed_file}")
                    entry = [x.strip() for x in intel_entry.strip().split(",")]
                    writer.writerow(entry)
        else:
            self.logger.info("No additions for SecOps Feed")

    def remove_from_etp_manual_blacklist(self):
        if self.manual_blacklist:
            self.logger.info("Removing from manual blacklist")
            with fileinput.input(blacklist_file, inplace=True) as file:
                for line in file:
                    if line.strip() in self.manual_blacklist:
                        self.logger.info(f"Removing {line} from {blacklist_file}")
                    else:
                        print(line, end="")
        else:
            self.logger.info("No removals for manual blacklist")

    def add_to_sps_intel_file(self):
        if self.whitelist or self.blacklist:
            with open(sps_intel_update_file, "w", newline="") as file:
                writer = csv.writer(file)
                for intel_entry in self.whitelist:
                    writer.writerow([intel_entry])

                for intel_entry in self.blacklist:
                    writer.writerow([intel_entry])

    def transfer_sps_update_file(self): 
        self.update_triggered = False
        if self.whitelist or self.blacklist:
            scp_command = [
                "scp",
                "-i",
                private_key_path,
                f"-J {jump_host_username}@{jump_host_ip}",
                sps_intel_update_file,
                f"{destination_username}@{destination_ip}:{destination_intel_file_path}"
            ]

            try:
                result = subprocess.run(scp_command, check=True, capture_output=True, text=True)
                print("File copied successfully.")
                self.logger.debug(result.stdout)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"ERROR Processing Whitelist Entities: {e}")
                self.logger.error(f"SCP command failed!")
                self.logger.error(f"Error message: {e.stderr}")
                self.logger.error(f"Return code: {e.returncode}")
                self.add_error_comment = True
                self.error_comment = (
                    "Failed to transfer intel updates to VM.\n"
                    + f"Error: {e.stderr}\n"
                )
        
    def trigger_sps_intel_update(self):
        if self.add_error_comment is False:
            self.update_triggered = True
            if self.whitelist or self.blacklist:
                ssh_command = [
                    "ssh",
                    "-i",
                    private_key_path,
                    f"-J {jump_host_username}@{jump_host_ip}",
                    f"{destination_username}@{destination_ip}",
                    f"python3 {intel_processor_path}", 
                ]

                try:
                    result = subprocess.run(ssh_command, check=True, capture_output=True, text=True)
                    intel_update_results = result.stdout.lower()
                    if '"success": false' in intel_update_results:
                        self.update_triggered = False
                        self.error_comment = (
                            "*{color:#de350b}!!! Failed to trigger intel update !!!{color}*"
                            + "{code:java} \n"
                            + intel_update_results
                            + "{code}"
                        )
                    self.logger.debug(result.stdout)
                except subprocess.CalledProcessError as e:
                    self.update_triggered = False
                    self.logger.error(f"ERROR Processing Whitelist Entities: {e}")
                    self.logger.error(f"SSH command failed!")
                    self.logger.error(f"Error message: {e.stderr}")
                    self.logger.error(f"Return code: {e.returncode}")
                    self.add_error_comment = True
                    self.error_comment = (
                        "*{color:#de350b}!!! Failed to trigger intel update !!!{color}*"
                        + "{code:java} \n"
                        + f"Error: {e.stderr}\n"
                        + "{code}"
                    )

    def update_indicator(self, entry):
        entry.is_valid_update = True
        
        if not entry.approved_intel_change:
            entry.is_valid_update = False
            return

        entry.approved_intel_change = entry.approved_intel_change.replace("+++ ", "").replace("--- ", "")
