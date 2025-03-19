#!/usr/bin/python3

import ast
import csv
import json
import time
from datetime import datetime

import requests
from config import logger, previous_queries_file, vt_api_key


class VirusTotalFetcher:
    previous_queries = {}
    vt_request_count = 0
    vt_api_threshold = 200

    def __init__(self, indicator) -> None:
        self.indicator = indicator
        self.previous_vt_query = None
        
    def set_vt_link(self):
        self.indicator.vt_link = (
            f"https://www.virustotal.com/gui/domain/{self.indicator.fqdn}/detection"
        )

    def prepare_indicator(self) -> None:
        self.indicator.fqdn = self.indicator.fqdn.replace("[", "").replace("]", "")
        if self.indicator.indicator_type.lower() == "domain":
            if self.indicator.fqdn[-1] == ".":
                self.indicator.fqdn = self.indicator.fqdn[:-1]

    def load_previous_queries():
        with open(previous_queries_file, "r") as f:
            file = csv.reader(f)
            
            for line in file:
                fqdn = line[0]
                vt_indications = int(line[1])
                creation_date = int(line[2]) if line[2].isdigit() else '-'
                last_scanned = int(line[3]) if line[3].isdigit() else '-'
                categories = ast.literal_eval(line[4])
                tags = ast.literal_eval(line[5])
                data_source = line[6]
                has_vt_data = str_to_bool(line[7])
                days_since_creation = int(line[8]) if line[8].isdigit() else '-'
                days_since_last_scanned = int(line[9]) if line[9].isdigit() else '-'
            
                VirusTotalFetcher.previous_queries[fqdn] = {
                    "vt_indications": vt_indications,
                    "creation_date": creation_date,
                    "last_scanned": last_scanned,
                    "categories": categories,
                    "tags": tags,
                    "data_source": data_source,
                    "has_vt_data": has_vt_data,
                    "days_since_creation": days_since_creation,
                    "days_since_last_scanned": days_since_last_scanned,
                }

    def write_vt_data(self):
        with open(previous_queries_file, "a", newline="") as f:
            writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_MINIMAL)
            writer.writerow([
                self.indicator.fqdn,
                self.indicator.vt_indications,
                self.indicator.creation_date,
                self.indicator.last_scanned,
                self.indicator.categories,
                self.indicator.tags,
                self.indicator.data_source,
                self.indicator.has_vt_data,
                self.indicator.days_since_creation,
                self.indicator.days_since_last_scanned,
            ])
            
    def get_previous_query(self):
        try:
            self.previous_vt_query = VirusTotalFetcher.previous_queries.get(self.indicator.fqdn)

            if self.previous_vt_query:
                self.indicator.vt_indications = self.previous_vt_query.get("vt_indications")
                self.indicator.creation_date = self.previous_vt_query.get("creation_date")
                self.indicator.last_scanned = self.previous_vt_query.get("last_scanned")
                self.indicator.categories = self.previous_vt_query.get("categories")
                self.indicator.tags = self.previous_vt_query.get("tags")
                self.indicator.data_source = self.previous_vt_query.get("data_source")
                self.indicator.has_vt_data = self.previous_vt_query.get("has_vt_data")
                self.indicator.days_since_creation = self.previous_vt_query.get("days_since_creation")
                self.indicator.days_since_last_scanned = self.previous_vt_query.get("days_since_last_scanned")
                self.indicator.attribution = "-"
                self.indicator.attribution_id = "-"
                self.indicator.attribution_description = "-"
        except Exception as e:
            print(f"Failed to read previous VT query: {e}")
            logger.error(f"Failed to read previous VT query: {e}")
            raise

    def scan_domain(self):
        self.vt_analysis_url = f"https://www.virustotal.com/api/v3/domains/{self.indicator.fqdn}/analyse"

        headers = {
            "accept": "application/json",
            "x-apikey": vt_api_key
        }

        response = requests.post(self.vt_analysis_url, headers=headers)
        response_json = json.loads(response.text)
        response_data = response_json.get("data", None)

        if str(response.status_code).startswith("2") and response_data:
            self.indicator.rescan_id = response_data.get("id", None)
        else:
            self.indicator.rescan_id = None
            
    def analyse_vt_rescan(self):
        if self.indicator.rescan_id:
            attempt = 1
            scan_complete = False
            
            url = f"https://www.virustotal.com/api/v3/analyses/{self.indicator.rescan_id}"
            
            headers = {
                "accept": "application/json",
                "x-apikey": vt_api_key
            }
            while scan_complete is False:
                response = requests.get(url, headers=headers)

                if str(response.status_code).startswith("2"):
                    self.decoded_response = json.loads(response.text)
                    status = self.decoded_response.get('data', {}).get('attributes', {}).get('status', "")
                    if status == "completed":
                        self.rescan = True
                        self.assign_results()
                        scan_complete = True
                    else:
                        attempt += 1
                        
                        if attempt == 13:
                            scan_complete = True
                        else:
                            time.sleep(5)                        
                else:
                    scan_complete = True
                
    def get_external_data(self):
        if VirusTotalFetcher.vt_request_count <= VirusTotalFetcher.vt_api_threshold:
            VirusTotalFetcher.vt_request_count += 1
            fqdn = self.indicator.fqdn
            request_headers = {
                "Accept": "application/json",
                "x-apikey": vt_api_key,
            }
            fqdn_vt_api = f"https://www.virustotal.com/api/v3/domains/{fqdn}"
            try:
                logger.info(f"{fqdn}: Fetching VT data")
                response = requests.get(fqdn_vt_api, headers=request_headers)
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

    def save_results(self):
        VirusTotalFetcher.previous_queries[self.indicator.fqdn] = {
            "vt_indications": self.indicator.vt_indications,
            "creation_date": self.indicator.creation_date,
            "last_scanned": self.indicator.last_scanned,
            "categories": self.indicator.categories,
            "tags": self.indicator.tags,
            "data_source": self.indicator.data_source,
            "has_vt_data": self.indicator.has_vt_data,
            "days_since_creation": self.indicator.days_since_creation,
            "days_since_last_scanned": self.indicator.days_since_last_scanned,
            "attribution": self.indicator.attribution,
            "attribution_id": self.indicator.attribution_id,
            "attribution_description": self.indicator.attribution_description,
        }
                    
    def assign_results(self):
        try:
            self.today = datetime.today()
            if self.rescan is True:
                data_response = self.decoded_response.get("data", {})
                filtered_response = data_response.get("attributes", {})
                last_analysis_stats = filtered_response.get("stats", {})
                vt_indications = last_analysis_stats.get("malicious", "-")
                if vt_indications != "-":
                    self.indicator.vt_indications = vt_indications
                    self.indicator.has_vt_data = True
                self.indicator.last_scanned = filtered_response.get("date", "")
                if self.indicator.last_scanned != "-":
                    last_scanned_datetime = datetime.utcfromtimestamp(self.indicator.last_scanned)
                    self.indicator.days_since_last_scanned = (self.today - last_scanned_datetime).days
                else:
                    self.indicator.days_since_last_scanned = 365
            else:
                logger.info(f"Attributing VT data")
                data_response = self.decoded_response.get("data", {})
                filtered_response = data_response.get("attributes", {})
                last_analysis_stats = filtered_response.get("last_analysis_stats", {})
                if not last_analysis_stats:
                    last_analysis_stats = filtered_response.get("stats", {})
                self.indicator.vt_indications = last_analysis_stats.get("malicious", "-")
                self.indicator.creation_date = filtered_response.get("creation_date", "")
                self.indicator.last_scanned = filtered_response.get("last_analysis_date", "")
                if not self.indicator.last_scanned:
                    self.indicator.last_scanned = "-"
                self.indicator.categories = filtered_response.get("categories", {})
                self.indicator.analysis_results = filtered_response.get(
                    "last_analysis_results", ""
                )
                self.indicator.tags = filtered_response.get("tags", "")
                self.indicator.data_source = "External"
                self.indicator.has_vt_data = True

                if self.indicator.creation_date:
                    creation_datetime = datetime.utcfromtimestamp(self.indicator.creation_date)
                    self.indicator.days_since_creation = (self.today - creation_datetime).days
                else:
                    self.indicator.days_since_creation = 100

                if self.indicator.last_scanned != "-":
                    last_scanned_datetime = datetime.utcfromtimestamp(self.indicator.last_scanned)
                    self.indicator.days_since_last_scanned = (self.today - last_scanned_datetime).days
                else:
                    self.indicator.days_since_last_scanned = 365
        except Exception as e:
            print(f"Error attributing VT data to {self.indicator.fqdn}: {e}")
            logger.error(f"Error attributing VT data to {self.indicator.fqdn}: {e}")
            self.no_data()
            raise

    def no_data(self):
        logger.info(f"Assigning no data to {self.indicator.fqdn}")
        self.indicator.has_vt_data = False
        self.indicator.vt_indications = "-"
        self.indicator.creation_date = "-"
        self.indicator.last_scanned = "-"
        self.indicator.categories = "-"
        self.indicator.response_code = "-"
        self.indicator.analysis_results = "-"
        self.indicator.tags = "-"
        self.indicator.data_source = "-"
        self.indicator.days_since_creation = "-"
        self.indicator.days_since_last_scanned = "-"
        self.indicator.attribution = "-"
        self.indicator.attribution_id = "-"
        self.indicator.attribution_description = "-"

    def get_domain_attributions(self):
        phishing = 0
        malware = 0
        cnc = 0
        vendor_categories = ""
        tags = ""
        attribute_found = False

        # First check vendor categorisations
        if self.indicator.categories != "-":
            vendor_categories = ",".join(list(self.indicator.categories.values()))

        if self.indicator.tags:
            tags = ",".join(self.indicator.tags)

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
                vendors = self.indicator.analysis_results.keys()
            except:
                self.indicator.attribution = "No Threat Attribution"
            else:
                for vendor in vendors:
                    result = self.indicator.analysis_results[vendor]["result"]
                    try:
                        if result.lower() == "phishing":
                            phishing += 1
                        elif result.lower() == "malware":
                            malware += 1
                        elif result.lower() == "malicious":
                            malware += 1
                        else:
                            pass
                    except:
                        continue

        if phishing == 0 and malware == 0 and cnc == 0:
            self.indicator.attribution = "No Threat Attribution"
            self.indicator.attribution_id = ""
            self.indicator.attribution_description = ""
        elif phishing == 0 and malware == 0:
            self.indicator.attribution = "CNC"
            self.indicator.attribution_id = "5110"
            self.indicator.attribution_description = "used in CnC activity"
        elif malware > phishing:
            self.indicator.attribution = "Malware"
            self.indicator.attribution_id = "5070"
            self.indicator.attribution_description = "used in Malware activity"
        else:
            self.indicator.attribution = "Phishing"
            self.indicator.attribution_id = "5090"
            self.indicator.attribution_description = "Phishing site"


def str_to_bool(string):
    if type(string) == str:
        return True if string.lower() == "true" else False
    else:
        return string