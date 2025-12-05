#!/usr/bin/python3

import csv
import re

import requests
from config import api_key, get_logger, sps_intel_update_file
from requests.packages.urllib3.exceptions import InsecureRequestWarning


logger = get_logger("logs_intel_updater.txt")


class IntelUpdater:
    def __init__(
        self, logger, update_line, reason_given=None, expiration=None, confidence=None
    ) -> None:
        self.logger = logger
        self.update_line = update_line
        self.fqdn = ""
        self.ticket_id = ""
        self.feed = ""
        self.valid_update = False
        self.expiration = expiration
        self.confidence = confidence
        self.reason_given = reason_given

    def parse_update(self):
        update_data = self.update_line

        if len(update_data) == 3:
            self.fqdn = update_data[0]
            self.ticket_id = update_data[1]
            self.feed = update_data[2]

            if self.fqdn and self.ticket_id and self.feed:
                self.valid_update = True
            else:
                self.logger.info(f"Skipped - missing data: {update_data}")
        else:
            self.logger.info(f"Skipped - Not valid format: {update_data}")

    def get_reason(self):
        if self.reason_given:
            self.reason = f"Internal|Carrier|SecOps|{self.reason_given}"
        else:
            self.reason = f"Internal|Carrier|SecOps|{self.ticket_id}"
            self.logger.info(f"Created reason string: {self.reason}")

    def get_update_parameters(self):
        self.logger.info(f"Updating parameters")
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
        elif self.feed.lower() == "unidentified":
            self.intel_feed = "tps-unidentified"
            self.expiration_time = "180 days"
            self.threat_id = 601
        else:
            self.intel_feed = ""
            self.expiration_time = ""
            self.threat_id = ""

        if self.expiration:
            self.expiration_time = self.expiration
        self.logger.info(
            f"Created parameters - feed: {self.intel_feed}, expiration: {self.expiration_time}, threat_id: {self.threat_id}"
        )

    def create_update_command(self):
        self.confidence = 0.95 if self.confidence is None else self.confidence
        self.command = {
            "name": self.fqdn,
            "blockability_class": self.intel_feed,
            "threat_type": self.threat_id,
            "time_expire": self.expiration_time,
            "reason": self.reason,
            "confidence": self.confidence,
            "api_key": api_key,
        }
        self.logger.info(f"Created command: {self.command}")

    def execute_command(self):
        self.logger.info(f"Executing command")
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        url = "https://fresh-milk-feeds.rad.nominum.com:51000/api/v1/entry/add"
        response = requests.post(url, data=self.command, verify=False)
        logger.info(f"Response text: {response.text}")
        self.response_text = response.text
        if str(response.status_code).startswith("2"):
            self.logger.info(f"{self.fqdn} added to {self.intel_feed}")
        else:
            self.logger.info(f"Failed to add {self.fqdn} to {self.intel_feed}")

    def clean_domain(self):
        self.logger.info(f"Cleaning {self.fqdn}")
        pattern = re.compile(
            r"^(?=.{1,253}$)((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}\.?$",
            re.IGNORECASE,
        )

        #     "((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}"
        # )

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
        self.logger.info(f"Cleaned {self.fqdn}")

        if not pattern.match(self.fqdn):
            self.logger.info(f"{self.fqdn} not a valid FQDN")
            self.valid_update = False

    def create_linode_commands(self):
        urls = [
            "https://freshmilk.prod-us-ord.prod.spof.akaetp.net/api/v1/entry/add",
            "https://freshmilk.staging.qa.spof.akaetp.net/api/v1/entry/add",
        ]

        data = {
            "name": self.fqdn,
            "blockability_class": self.intel_feed,
            "threat_type": self.threat_id,
            "time_expire": self.expiration_time,
            "reason": self.reason,
            "confidence": self.confidence,
            "api_key": api_key,
        }

        for url in urls:
            response = requests.post(url, data=data, verify=False)
            logger.info(f"Response text: {response.text}")
            self.response_text = response.text
            if str(response.status_code).startswith("2"):
                self.logger.info(f"{self.fqdn} added to {self.intel_feed}")
            else:
                self.logger.info(f"Failed to add {self.fqdn} to {self.intel_feed}")


if __name__ == "__main__":
    data_strings = []
    with open(sps_intel_update_file, "r") as file:
        reader = csv.reader(file)
        intel_updates = [row for row in reader]

    for row in intel_updates:
        if row[0]:
            intel_updater = IntelUpdater(logger, row)
            intel_updater.parse_update()
            intel_updater.clean_domain()
            intel_updater.get_update_parameters()
            intel_updater.get_reason()
            # intel_updater.create_linode_commands()

            intel_updater.create_update_command()
            intel_updater.execute_command()
