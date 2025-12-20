import fileinput
import csv
from config import (
    WHITELIST_FILE,
    BLACKLIST_FILE,
    SECOPS_FEED_FILE,
    FEED_PROCESSOR_URL,
    FEED_PROCESSOR_URL2,
)
from typing import List
import requests


class IntelProcessor:
    def __init__(self, logger, intel_entries, feed_processor_api_key) -> None:
        self.logger = logger
        self.intel_entries = intel_entries
        self.feed_processor_api_key = feed_processor_api_key
        self.whitelist: List[str] = []
        self.whitelist_removal: List[str] = []
        self.blacklist: List[str] = []
        self.manual_blacklist: List[str] = []
        self.data_strings: List[str] = []
        self.add_error_comment: bool = False
        self.error_comment: List[str] = []
        self.summary_comment: List[str] = []

    def process_sps_indicators(self):
        for intel_entry in self.intel_entries:
            if intel_entry.is_approved is True:
                self.update_indicator(intel_entry)
                if intel_entry.is_valid_update is True:
                    if intel_entry.intel_list.lower() == "whitelist":
                        if intel_entry.operation.lower() == "add":
                            intel_entry.whitelist.append(intel_entry)
                            intel_entry.update_approved = True
                            self.whitelist.append(intel_entry)
                            self.logger.info(
                                f"{intel_entry.indicator.fqdn} identified for the allow list."
                            )
                        elif intel_entry.operation.lower() == "remove":
                            intel_entry.update_approved = True
                            intel_entry.whitelist_removal.append(intel_entry)
                            self.whitelist_removal.append(intel_entry)
                            self.logger.info(
                                f"{intel_entry.indicator.fqdn} identified for whitelist removal."
                            )
                    elif intel_entry.intel_list.lower() == "blacklist":
                        if intel_entry.operation.lower() == "add":
                            intel_entry.update_approved = True
                            intel_entry.blacklist.append(intel_entry)
                            self.blacklist.append(intel_entry)
                            self.logger.info(
                                f"{intel_entry.indicator.fqdn} identified for the block list."
                            )

        self.whitelist = list(set(self.whitelist))
        self.blacklist = list(set(self.blacklist))
        self.manual_blacklist = list(set(self.manual_blacklist))

    # def process_indicators(self):
    #     for intel_entry in self.intel_entries:
    #         if intel_entry.is_approved is True:
    #             self.update_indicator(intel_entry)
    #             if intel_entry.is_valid_update is True:
    #                 if intel_entry.intel_list.lower() == "whitelist":
    #                     if intel_entry.operation.lower() == "add":
    #                         self.whitelist.append(intel_entry)
    #                         self.logger.info(
    #                             f"{intel_entry.indicator.fqdn} identified for the allow list."
    #                         )
    #                     elif intel_entry.operation.lower() == "remove":
    #                         self.whitelist_removal.append(intel_entry)
    #                         self.logger.info(
    #                             f"{intel_entry.indicator.fqdn} identified for whitelist removal."
    #                         )
    #                 elif intel_entry.intel_list.lower() == "blacklist":
    #                     if intel_entry.operation.lower() == "add":
    #                         self.blacklist.append(intel_entry)
    #                         self.logger.info(
    #                             f"{intel_entry.indicator.fqdn} identified for the block list."
    #                         )
    #                     elif intel_entry.operation.lower() == "remove":
    #                         self.manual_blacklist.append(intel_entry)
    #                         self.logger.info(
    #                             f"{intel_entry.indicator.fqdn} identified for manual blacklist removal."
    #                         )

    #     self.whitelist = list(set(self.whitelist))
    #     self.blacklist = list(set(self.blacklist))
    #     self.manual_blacklist = list(set(self.manual_blacklist))

    def process_indicators(self):
        for intel_entry in self.intel_entries:
            if intel_entry.is_approved is True:
                self.update_indicator(intel_entry)
                if intel_entry.is_valid_update is True:
                    if intel_entry.intel_list.lower() == "whitelist":
                        if intel_entry.operation.lower() == "add":
                            self.whitelist.append(intel_entry.approved_intel_change)
                            self.logger.info(
                                f"{intel_entry.indicator.fqdn} identified for the allow list."
                            )
                        elif intel_entry.operation.lower() == "remove":
                            self.whitelist_removal.append(
                                intel_entry.approved_intel_change
                            )
                            self.logger.info(
                                f"{intel_entry.indicator.fqdn} identified for whitelist removal."
                            )
                    elif intel_entry.intel_list.lower() == "blacklist":
                        if intel_entry.operation.lower() == "add":
                            self.blacklist.append(intel_entry.approved_intel_change)
                            self.logger.info(
                                f"{intel_entry.indicator.fqdn} identified for the block list."
                            )
                        elif intel_entry.operation.lower() == "remove":
                            self.manual_blacklist.append(
                                intel_entry.approved_intel_change
                            )
                            self.logger.info(
                                f"{intel_entry.indicator.fqdn} identified for manual blacklist removal."
                            )

        self.whitelist = list(set(self.whitelist))
        self.blacklist = list(set(self.blacklist))
        self.manual_blacklist = list(set(self.manual_blacklist))

    def add_to_etp_whitelist(self):
        if self.whitelist:
            self.logger.info("Adding to manual whitelist")
            with open(WHITELIST_FILE, "a", newline="") as file:
                writer = csv.writer(file, lineterminator="\n")
                for intel_entry in self.whitelist:
                    self.logger.info(f"Adding {intel_entry} to {WHITELIST_FILE}")
                    entry = [x.strip() for x in intel_entry.strip().split(",")]
                    writer.writerow(entry)
        else:
            self.logger.info("No additions for manual whitelist")

    def add_to_etp_blacklist(self):
        if self.blacklist:
            self.logger.info("Adding to SecOps Feed")
            with open(SECOPS_FEED_FILE, "a", newline="") as file:
                writer = csv.writer(file, lineterminator="\n")
                for intel_entry in self.blacklist:
                    self.logger.info(f"Adding {intel_entry} to {SECOPS_FEED_FILE}")
                    entry = [x.strip() for x in intel_entry.strip().split(",")]
                    writer.writerow(entry)
        else:
            self.logger.info("No additions for SecOps Feed")

    def remove_from_etp_manual_blacklist(self):
        if self.manual_blacklist:
            self.logger.info("Removing from manual blacklist")
            with fileinput.input(BLACKLIST_FILE, inplace=True) as file:
                for line in file:
                    if line.strip() in self.manual_blacklist:
                        self.logger.info(f"Removing {line} from {BLACKLIST_FILE}")
                    else:
                        print(line, end="")
        else:
            self.logger.info("No removals for manual blacklist")

    def linode_whitelist_addition(self, fqdn, ticket):
        urls = [
            FEED_PROCESSOR_URL,
            FEED_PROCESSOR_URL2,
        ]

        data = {
            "name": fqdn,
            "blockability_class": "alexa-whitelist-additions",
            "threat_type": "1000",
            "time_expire": "3650 days",
            "reason": f"Internal|Carrier|SecOps|{ticket}",
            "confidence": "0.95",
            "api_key": self.feed_processor_api_key,
        }

        for url in urls:
            self.logger.info(f"Sending update to Linode whitelist - {fqdn}")
            response = requests.post(url, data=data, verify=False)
            self.linode_update_status_code = str(response.status_code)
            self.linode_update_response = response.text
            self.logger.info(f"Response status code - {response.status_code}")
            self.logger.info(f"Response text - {response.text}")

    def linode_whitelist_removal(self, fqdn, ticket):
        urls = [
            FEED_PROCESSOR_URL,
            FEED_PROCESSOR_URL2,
        ]

        data = {
            "name": fqdn,
            "blockability_class": "alexa-whitelist-additions",
            "threat_type": "1000",
            "time_expire": "1 minute",
            "reason": f"Internal|Carrier|SecOps|{ticket}",
            "confidence": "0.95",
            "api_key": self.feed_processor_api_key,
        }

        for url in urls:
            self.logger.info(f"Sending update to Linode whitelist removal - {fqdn}")
            response = requests.post(url, data=data, verify=False)
            self.linode_update_status_code = str(response.status_code)
            self.linode_update_response = response.text
            self.logger.info(f"Response status code - {response.status_code}")
            self.logger.info(f"Response text - {response.text}")

    def linode_blocklist_update(self, fqdn, ticket, block_feed):
        if "phishing" in block_feed.lower():
            feed = "tps-phishing"
            threat_type = 402
        elif "malware" in block_feed.lower():
            feed = "tps-malware"
            threat_type = 302
        elif "botnet" in block_feed.lower():
            feed = "gix-vta-block"
            threat_type = 1000
        else:
            self.logger.info("no feed found: %s", block_feed)
            return

        data = {
            "name": fqdn,
            "blockability_class": feed,
            "threat_type": threat_type,
            "time_expire": "3650 days",
            "reason": f"Internal|Carrier|SecOps|{ticket}",
            "confidence": "0.95",
            "api_key": self.feed_processor_api_key,
        }

        urls = [
            FEED_PROCESSOR_URL,
            FEED_PROCESSOR_URL2,
        ]

        for url in urls:
            self.logger.info(f"Sending update to Linode blocklist - {fqdn}")
            response = requests.post(url, data=data, verify=False)
            self.linode_update_status_code = str(response.status_code)
            self.linode_update_response = response.text
            self.logger.info(f"Response status code - {response.status_code}")
            self.logger.info(f"Response text - {response.text}")

    def update_linode(self):
        for intel_entry in self.whitelist:
            entry = intel_entry.split(",")
            fqdn = entry[0]
            ticket = entry[1]

            data = {
                "name": fqdn,
                "blockability_class": "alexa-whitelist-additions",
                "threat_type": "1000",
                "time_expire": "3650 days",
                "reason": f"Internal|Carrier|SecOps|{ticket}",
                "confidence": "0.95",
                "api_key": self.feed_processor_api_key,
            }

            urls = [FEED_PROCESSOR_URL, FEED_PROCESSOR_URL2]

            for url in urls:
                response = requests.post(url, data=data, verify=False)
                self.linode_update_status_code = response.status_code
                self.linode_update_response = response.text

        for intel_entry in self.blacklist:
            entry = intel_entry.split(",")
            fqdn = entry[0]
            ticket = entry[1]
            block_feed = entry[2].lower()
            if "phishing" in block_feed:
                feed = "tps-phishing"
                threat_type = 402
            elif "malware" in block_feed:
                feed = "tps-malware"
                threat_type = 302
            elif "botnet" in block_feed:
                feed = "gix-vta-block"
                threat_type = 1000
            else:
                self.logger.info("no feed found: %s", entry)
                continue

            data = {
                "name": fqdn,
                "blockability_class": feed,
                "threat_type": threat_type,
                "time_expire": "3650 days",
                "reason": f"Internal|Carrier|SecOps|{ticket}",
                "confidence": "0.95",
                "api_key": self.feed_processor_api_key,
            }

            urls = [FEED_PROCESSOR_URL, FEED_PROCESSOR_URL2]

            for url in urls:
                response = requests.post(url, data=data, verify=False)
                # Print full response including headers
                # print("Status Code:", response.status_code)
                # print("Headers:", response.headers)
                # print("Body:", response.text)

    def update_indicator(self, entry):
        entry.is_valid_update = True

        if not entry.approved_intel_change:
            entry.is_valid_update = False
            return

        entry.approved_intel_change = entry.approved_intel_change.replace(
            "+++ ", ""
        ).replace("--- ", "")

    def generate_data_string_comment(self):
        summary_strings = []

        if self.summary_comment:
            summary_strings.append("*Successful Intel Updates*")
            for data_string in self.summary_comment:
                new_string = "|" + "|".join(data_string) + "|"
                summary_strings.append(new_string)

        if self.error_comment:
            summary_strings.append(
                "*{color:#de350b}!!! Failed Intel Updates !!!{color}*"
            )

            for data_string in self.error_comment:
                new_string = "|" + "|".join(data_string) + "|"
                summary_strings.append(new_string)

        self.data_string_comment = "\n".join(summary_strings)
