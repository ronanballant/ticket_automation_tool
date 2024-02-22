#!/usr/bin/python3


import base64
import json
from datetime import datetime

import requests

from config import interal_vt_api, logger, vt_api_key


class VirusTotalFetcher:
    vt_request_count = 0
    vt_api_threshold = 100

    def __init__(self, entity) -> None:
        self.entity = entity
        self.prepare_entity()
        self.get_vt_url()
        self.get_external_data()
        self.get_domain_attributions()

    def prepare_entity(self) -> None:
        self.entity.entity = self.entity.entity.replace("[", "").replace("]", "")
        if self.entity.entity_type.lower() == "domain":
            if self.entity.entity[-1] == ".":
                self.entity.entity = self.entity.entity[:-1]

        if self.entity.entity_type.lower() == "ipv4":
            ip = self.entity.entity.split("\\")[0]
            self.entity.entity = ip

    def get_vt_url(self):
        if self.entity.entity_type.lower() == "domain":
            self.entity.vt_url = (
                f"https://www.virustotal.com/api/v3/domains/{self.entity.entity}"
            )
        elif self.entity.entity_type.lower() == "url":
            encoded_url = (
                base64.urlsafe_b64encode(self.entity.entity.encode())
                .decode()
                .strip("=")
            )
            self.entity.vt_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        elif self.entity.entity_type.lower() == "ipv4":
            self.entity.vt_url = (
                f"https://www.virustotal.com/api/v3/ip_addresses/{self.entity.entity}"
            )
        else:
            self.entity.vt_url = None

    def get_external_data(self):
        today = datetime.today()
        if VirusTotalFetcher.vt_request_count <= VirusTotalFetcher.vt_api_threshold:
            domain = self.entity.domain

            request_headers = {
                "Accept": "application/json",
                "x-apikey": vt_api_key,
            }

            domain_vt_api = f"https://www.virustotal.com/api/v3/domains/{domain}"
            try:
                logger.info("{}: Fetching VT data", domain)
                response = requests.get(domain_vt_api, headers=request_headers)
                if response.status_code == 200:
                    decoded_response = json.loads(response.text)
                    data_response = decoded_response.get("data", {})
                    filtered_response = data_response.get("attributes", {})
                    last_analysis_stats = filtered_response.get(
                        "last_analysis_stats", ""
                    )
                    self.entity.positives = last_analysis_stats.get("malicious", "")
                    self.entity.creation_date = filtered_response.get(
                        "creation_date", ""
                    )
                    self.entity.last_seen = filtered_response.get(
                        "last_analysis_date", ""
                    )
                    self.entity.categories = filtered_response.get("categories", {})
                    self.entity.dns_records = filtered_response.get("last_dns_records")
                    self.entity.analysis_results = filtered_response.get(
                        "last_analysis_results", ""
                    )
                    self.entity.tags = filtered_response.get("tags", "")
                    self.entity.data_source = "External"
                    self.entity.has_data = True

                    if self.entity.creation_date:
                        creation_datetime = datetime.utcfromtimestamp(
                            self.entity.creation_date
                        )
                        self.entity.days_since_creation = (
                            today - creation_datetime
                        ).days
                    else:
                        self.entity.days_since_creation = 100

                    if self.entity.last_seen:
                        last_seen_datetime = datetime.utcfromtimestamp(
                            self.entity.last_seen
                        )
                        self.entity.days_since_last_seen = (
                            today - last_seen_datetime
                        ).days
                    else:
                        self.entity.days_since_last_seen = 365

                    logger.info("%s: VT query successful", self.entity.domain)
                else:
                    self.no_data()
                    logger.error("%s: VT Bad Response", self.entity.domain)
            except:
                self.no_data()
                logger.error("%s: Error parsing VT data", self.entity.domain)
            VirusTotalFetcher.vt_request_count += 1
        else:
            self.no_data()
            logger.error("%s: VT Failed - API Quota Reached", self.entity.domain)

    def no_data(self):
        logger.info("Assiging no data to {}", self.entity.domain)
        self.entity.has_data = False
        self.entity.positives = "-"
        self.entity.creation_date = "-"
        self.entity.last_seen = "-"
        self.entity.categories = "-"
        self.entity.response_code = "-"
        self.entity.analysis_results = "-"
        self.entity.tags = "-"
        self.entity.data_source = "-"
        self.entity.days_since_creation = "-"
        self.entity.days_since_last_seen = "-"

    def get_domain_attributions(self):
        phishing = 0
        malware = 0
        cnc = 0
        vendor_categories = ""
        tags = ""
        attribute_found = False

        # First check vendor categorisations
        if self.entity.categories != "-":
            vendor_categories = ",".join(list(self.entity.categories.values()))

        if self.entity.tags:
            tags = ",".join(self.entity.tags)

        if "phishing" in vendor_categories.lower():
            phishing += 1
            attribute_found = True
        elif ("malware" or "infection") in vendor_categories.lower():
            malware += 1
            attribute_found = True
        elif ("dga" or "bot") in tags.lower():
            cnc += 1
            attribute_found = True

        # Check vendor analysis results for attributions if not categorisations were found
        if attribute_found == False:
            try:
                vendors = self.entity.analysis_results.keys()
            except:
                self.entity.attribution = "No Threat Attribution"
            else:
                for vendor in vendors:
                    result = self.entity.analysis_results[vendor]["result"]
                    try:
                        if result.lower() == "phishing":
                            phishing += 1
                        elif result.lower() == "malware":
                            malware += 1
                        else:
                            pass
                    except:
                        continue

        if phishing == 0 and malware == 0 and cnc == 0:
            self.entity.attribution = "No Threat Attribution"
            self.entity.attribution_id = ""
            self.entity.attribution_description = ""
        elif phishing == 0 and malware == 0:
            self.entity.attribution = "CNC"
            self.entity.attribution_id = "5110"
            self.entity.attribution_description = "used in CnC activity"
        elif malware > phishing:
            self.entity.attribution = "Malware"
            self.entity.attribution_id = "5070"
            self.entity.attribution_description = "used in Malware activity"
        else:
            self.entity.attribution = "Phishing"
            self.entity.attribution_id = "5090"
            self.entity.attribution_description = "Phishing site"

    # def get_internal_data(self):
    #     domain = self.entity.domain
    #     today = datetime.today()
    #     internal_path = f"{interal_vt_api}{domain}{&domain_only=True}"

    #     try:
    #         response = requests.get(internal_path)

    #         if response.status_code == 200:
    #             response_json = response.json()
    #             if (
    #                 "VT-categories" in response_json
    #                 and isinstance(response_json["VT-categories"], list)
    #                 and response_json["VT-categories"]
    #             ):
    #                 results = response_json.get("VT-categories")[0]
    #                 self.entity.data_source = 'Internal'
    #                 self.entity.positives = results.get("positives", '')
    #                 self.entity.resolution = results.get('resolution', '')
    #                 self.entity.response_code = results.get('Response code', '')
    #                 self.entity.detections = results.get('detections', {})
    #                 self.entity.last_seen = results.get('last_seen', '')
    #                 self.entity.first_seen = results.get('first_seen', '')
    #                 self.entity.days_since_creation = 100
    #                 self.entity.categories = {}
    #                 for item in response_json.get("VT-categories", {}):
    #                     for key, value in item.items():
    #                         if "category" in key.lower() and value:
    #                             self.entity.categories[key] = value
    #                 response.close()

    #                 if self.entity.last_seen:
    #                     last_seen_datetime = datetime.strptime(self.entity.last_seen, "%Y-%m-%d %H:%M:%S")
    #                     self.entity.days_since_last_seen = (today - last_seen_datetime).days
    #                 else:
    #                     self.entity.days_since_last_seen = 365

    #                 if self.entity.days_since_last_seen >= 30:
    #                     self.check_externally = True
    #                     self.entity.has_data = False
    #                     logger.info("%s: Internal data expired", self.entity.domain)
    #                 else:
    #                     self.check_externally = False
    #                     self.entity.has_data = True
    #                     self.entity.data_source = 'Internal'
    #                     logger.info("%s: Internal scan, Positives: %s", self.entity.domain, self.entity.positives)
    #             else:
    #                 response.close()
    #                 self.check_externally = True
    #                 self.entity.has_data = False
    #                 logger.info("%s: Internal scan has no results", self.entity.domain)
    #         else:
    #             response.close()
    #             self.check_externally = True
    #             self.entity.has_data = False
    #             logger.info(
    #                 "%s: Internal request failed with status code: %s", self.entity.domain, response.status_code
    #             )
    #     except Exception as e:
    #         self.check_externally = True
    #         logger.error("%s: Internal scan failed\n%s Error:", self.entity.domain, e)
