#!/usr/bin/python3

import datetime
import json
import re

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from config import (api_key, destination_region, directory_prefix, get_logger,
                    secops_s3_aws_access_key, secops_s3_aws_secret_key,
                    secops_s3_bucket, secops_s3_endpoint,
                    sps_intel_update_s3_path, update_responses_s3_path)
from s3_client import S3Client


logger = get_logger("logs_s3_intel_updater.txt")


class IntelUpdater:
    def __init__(self, logger, update_line) -> None:
        self.logger = logger
        self.update_line = update_line
        self.fqdn = ""
        self.ticket_id = ""
        self.feed = ""
        self.valid_update = False

    def parse_update(self):
        update_data = (
            self.update_line.replace('"', "").replace("'", "").strip().split(",")
        )

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
        else:
            self.intel_feed = ""
            self.expiration_time = ""
            self.threat_id = ""
        self.logger.info(
            f"Created parameters - feed: {self.intel_feed}, expiration: {self.expiration_time}, threat_id: {self.threat_id}"
        )

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
        self.logger.info(f"Created command: {self.command}")

    def execute_command(self):
        self.logger.info(f"Executing command")
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        url = "https://fresh-milk-feeds.rad.nominum.com:51000/api/v1/entry/add"
        response = requests.post(url, data=self.command, verify=False)
        self.logger.info(f"Response text: {response.text}")
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


if __name__ == "__main__":
    s3_client = S3Client(
        logger,
        destination_region,
        secops_s3_endpoint,
        secops_s3_bucket,
        secops_s3_aws_access_key,
        secops_s3_aws_secret_key,
        directory_prefix,
    )
    s3_client.initialise_client()
    s3_client.read_s3_file(sps_intel_update_s3_path)
    data = s3_client.file_content.strip().split("\n")
    logger.info(f"FQDNs to search: {data}")
    intel_updates = [row.strip().replace("'","") for row in data]
    logger.info(f"intel_updates: {intel_updates}")
    if intel_updates[0]:
        responses = []
        for row in intel_updates:
            if row[0]:
                logger.info(f"Processing: {row}")
                intel_updater = IntelUpdater(logger, row)
                intel_updater.parse_update()
                intel_updater.clean_domain()
                intel_updater.get_update_parameters()
                intel_updater.get_reason()
                intel_updater.create_update_command()
                intel_updater.execute_command()
                responses.append(intel_updater.response_text)

        print("responses", responses)
        with open("intel_update_responses.json", "w") as file:
            json.dump(responses, file, indent=4)

        s3_client.write_file("intel_update_responses.json", update_responses_s3_path)
