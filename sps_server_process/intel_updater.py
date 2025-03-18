#!/usr/bin/python3

import csv
import datetime
import re

import requests
from config import api_key, logger, sps_intel_update_file
from intel_finder import IntelFinder
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class IntelUpdater:
    def __init__(self, update_line) -> None:
        self.update_line = update_line
        self.fqdn = ""
        self.ticket_id = ""
        self.feed = ""
        self.valid_update = False

    def parse_update(self):
        update_data = (
            self.update_line.replace('"', '')
            .replace("'", "")
            .strip()
            .split(",")
        )

        if len(update_data) == 3:
            self.fqdn = update_data[0]
            self.ticket_id = update_data[1]
            self.feed = update_data[2]
            
            if self.fqdn and self.ticket_id and self.feed:
                self.valid_update = True
            else:
                logger.info(f"Skipped - missing data: {update_data}")
        else:
            logger.info(f"Skipped - Not valid format: {update_data}")

    def get_reason(self):
        self.reason = f"Internal|Carrier|SecOps|{self.ticket_id}"
        logger.info(f"Created reason string: {self.reason}")

    def get_update_parameters(self):
        logger.info(f"Updating parameters")
        if self.feed.lower() == "whitelist":
            self.intel_feed = "alexa-whitelist-additions"
            self.expiration_time = "3650 days"
            self.threat_id = 1000
        elif self.feed.lower() == "malware":
            self.intel_feed = "tps-malware"
            self.expiration_time = "180 days"
            self.threat_id = 301
        elif self.feed.lower() == "phishing":
            self.intel_feed = "tps-phishing"
            self.expiration_time = "180 days"
            self.threat_id = 401
        elif self.feed.lower() == "botnet":
            self.intel_feed = "gix-vta-block"
            self.expiration_time = "180 days"
            self.threat_id = 1000
        else:
            self.intel_feed = ""
            self.expiration_time = ""
            self.threat_id = ""
        logger.info(f"Created parameters - feed: {self.intel_feed}, expiration: {self.expiration_time}, threat_id: {self.threat_id}")


    def create_update_command(self):
        self.command = {
            "name": self.fqdn,
            "blockability_class": self.intel_feed,
            "threat_type": self.threat_id,
            "time_expire": self.expiration_time,
            "reason": self.reason,
            "confidence": 0.95,
            "api_key": api_key,
        }
        logger.info(f"Created command: {self.command}")

    def get_domain_data(self):
        logger.info(f"Fetching {self.fqdn} intel data")
        # intel = IntelFinder(self.fqdn)
        # intel.get_intel_feed()
        # self.current_feed = intel.feed
        # self.current_source = intel.source

    def execute_command(self):
        logger.info(f"Executing command")
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        url = "https://fresh-milk-feeds.rad.nominum.com:51000/api/v1/entry/add"
        response = requests.post(url, data=self.command, verify=False)
        print(response.text)

        if str(response.status_code).startswith("2"):
            logger.info(f"{self.fqdn} added to {self.intel_feed}")
        else:
            logger.info(f"Failed to add {self.fqdn} to {self.intel_feed}")

    def clean_domain(self):
        logger.info(f"Cleaning {self.fqdn}")
        pattern = re.compile(
            "((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}"
        )

        self.fqdn = (
            self.fqdn.replace("'", "")
            .replace('"', "")
            .replace("[", "")
            .replace("]", "")
            .replace(" ", "")
            .replace("/", "")
            .replace("\\", "")
            .replace("=", "")
            .replace("<", "")
            .replace(">", "")
            .replace("?", "")
            .replace("http:", "")
            .replace("https:", "")
            .replace("www.", "")
        )
        logger.info(f"Cleaned {self.fqdn}")

        if not pattern.match(self.fqdn):
            logger.info(f"{self.fqdn} not a valid FQDN")
            self.valid_update = False


if __name__ == "__main__":
    data_strings = []
    with open(sps_intel_update_file, "r") as file:
        reader = csv.reader(file)
        intel_updates = [row for row in reader]

    for row in intel_updates:
        if row[0]:
            intel_updater = IntelUpdater(row[0])
            intel_updater.parse_update()
            intel_updater.clean_domain()
            intel_updater.get_update_parameters()
            intel_updater.get_reason()
            intel_updater.create_update_command()
            # intel_updater.get_domain_data()
            # intel_updater.generate_data_string()
            intel_updater.execute_command()

    # with open("data_strings.csv", "w") as file:
    #     for row in data_strings:
    #         writer = csv.writer(file)
    #         writer.writerow([row])
