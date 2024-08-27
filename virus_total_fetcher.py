#!/usr/bin/python3


import base64
import json
from datetime import datetime

import requests

from config import logger, vt_api_key


class VirusTotalFetcher:
    previous_queries = {}
    vt_request_count = 0
    vt_api_threshold = 200

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

    def get_previous_query(self):
        try:
            self.previous_query = VirusTotalFetcher.previous_queries.get(self.entity.domain)
        except Exception as e:
            print(f"Failed to read previous VT query: {e}")
            logger.error(f"Failed to read previous VT query: {e}")
            raise
    def get_external_data(self):
        self.get_previous_query()

        if self.previous_query:
            response = self.previous_query
            if response.status_code == 200:
                self.decoded_response = json.loads(response.text)
            self.assign_results()
        else:
            self.entity.vt_link = f"https://www.virustotal.com/gui/domain/{self.entity.domain}/detection"
            if VirusTotalFetcher.vt_request_count <= VirusTotalFetcher.vt_api_threshold:
                VirusTotalFetcher.vt_request_count += 1
                domain = self.entity.domain
                request_headers = {
                    "Accept": "application/json",
                    "x-apikey": vt_api_key,
                }
                domain_vt_api = f"https://www.virustotal.com/api/v3/domains/{domain}"
                try:
                    logger.info(f"{domain}: Fetching VT data")
                    response = requests.get(domain_vt_api, headers=request_headers)
                    VirusTotalFetcher.previous_queries[self.entity.domain] = response 
                except Exception as e:
                    self.no_data()
                    print(f"Error querying VT API: {e}")
                    logger.error(f"Error querying VT API: {e}")
                    raise
                else:
                    if response.status_code == 200:
                        self.decoded_response = json.loads(response.text)
                        self.assign_results()
                    else:
                        self.no_data()
                        print(f"Bad VT Response for: {response.status_code}")
                        logger.error(f"Bad VT Response for: {response.status_code}")
            else:
                self.no_data()
                print("VT query failed - API quota reached")
                logger.error("VT query failed - API quota reached")

    def assign_results(self):
        try:
            logger.info(f"Attributing VT data")
            today = datetime.today()
            data_response = self.decoded_response.get("data", {})
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
            if not self.entity.last_seen:
                self.entity.last_seen = "-"
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

            if self.entity.last_seen != "-":
                last_seen_datetime = datetime.utcfromtimestamp(
                    self.entity.last_seen
                )
                self.entity.days_since_last_seen = (
                    today - last_seen_datetime
                ).days
            else:
                self.entity.days_since_last_seen = 365
        except Exception as e:
            print(f"Error attributing VT data to {self.entity.domain}: {e}")
            logger.error(f"Error attributing VT data to {self.entity.domain}: {e}")
            raise

    def no_data(self):
        logger.info(f"Assigning no data to {self.entity.domain}")
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
