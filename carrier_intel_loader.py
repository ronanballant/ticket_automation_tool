import ast
import subprocess

from config import (destination_ip, destination_username, intel_fetcher_path,
                    jump_host_ip, jump_host_username, private_key_path)


class CarrierIntelLoader:
    previous_queries = {}

    def __init__(self, logger, client) -> None:
        self.logger = logger
        self.client = client
        self.results = None

    def read_previous_queries(self):
        try:
            self.results[self.indicator.candidate] = CarrierIntelLoader.previous_queries.get(
                self.indicator.candidate, None
            )
        except Exception as e:
            self.logger.error(f"Failed to read previous Intel query: {e}")
            raise

    def fetch_intel(self):
        ssh_command = [
            "ssh",
            "-i",
            private_key_path,
            "-J {}@{}".format(jump_host_username, jump_host_ip),
            "{}@{}".format(destination_username, destination_ip),
            "python3 {} -d '{}'".format(intel_fetcher_path, self.indicator.candidate),
        ]

        try:
            result = subprocess.run(
                ssh_command, check=True, capture_output=True, text=True
            )
            self.logger.info(f"SPS Intel query sent for {self.indicator.candidate}")
            self.results = ast.literal_eval(result.stdout)
            CarrierIntelLoader.previous_queries[self.indicator.candidate] = self.results
        except Exception as e:
            self.logger.error(f"Error querying SPS intel: {e}")
            self.results = None

    def assign_results(self):
        try:
            self.logger.info(f"Attributing intel to {self.indicator.fqdn}")
            result = self.results.get(self.indicator.candidate)
            if result:
                self.indicator.is_in_intel = str_to_bool(result.get("is_in_intel", "-"))
                self.indicator.subdomain_only = str_to_bool(result.get("subdomain_only"))
                if self.indicator.is_in_intel is True:
                    self.indicator.intel_feed = result.get("intel_feed", "-")
                    self.indicator.intel_confidence = result.get("intel_confidence", "-")
                    if self.indicator.intel_confidence != "-":
                        if self.indicator.intel_confidence:
                            self.indicator.intel_confidence = float(
                                self.indicator.intel_confidence
                            )
                    self.indicator.subdomain_count = result.get("subdomain_count", 0)
                    self.indicator.url_count = result.get("url_count", 0)
                    self.indicator.intel_source = result.get("intel_source", "-").replace(
                        "|", "/"
                    )
                    self.indicator.e_list_entry = str_to_bool(
                        result.get("e_list_entry", False)
                    )

                else:
                    self.no_intel()
            else:
                self.no_intel()
        except Exception as e:
            self.logger.error(f"Error attributing SPS intel: {e}")
            raise

    def no_intel(self):
        self.indicator.intel_feed = "-"
        self.indicator.intel_confidence = "-"
        self.indicator.intel_source = "-"
        self.indicator.confidence_level = "-"
        self.indicator.subdomain_count = 0
        self.indicator.url_count = 0
        self.indicator.is_in_intel = False
        self.indicator.e_list_entry = False
        self.indicator.subdomain_only = False
        CarrierIntelLoader.previous_queries[self.indicator.candidate] = {}

    def no_s3_intel(self):
        self.indicator.intel_feed = "-"
        self.indicator.intel_confidence = "-"
        self.indicator.intel_source = "-"
        self.indicator.confidence_level = "-"
        self.indicator.subdomain_count = 0
        self.indicator.url_count = 0
        self.indicator.is_in_intel = False
        self.indicator.e_list_entry = False
        self.indicator.subdomain_only = False
        CarrierIntelLoader.previous_queries[self.indicator.candidate] = {}

    def read_previous_s3_queries(self):
        try:
            self.result = CarrierIntelLoader.previous_queries.get(
                self.indicator.candidate, None
            )
        except Exception as e:
            self.logger.error(f"Failed to read previous Intel query: {e}")
            raise

    def query_s3_intel(self):
        self.result = self.client.query_fqdn(self.indicator.candidate)

    def assign_s3_intel(self):
        intel_feeds = []
        pairs = self.result.get("category_reason_pairs", [])
        for pair in pairs:
            feed, source = pair.split(":")
            intel_feeds.append((feed.strip(), source.strip()))

        intel_feeds.sort(key=lambda x: x[0], reverse=True)
        self.indicator.intel_feed_list = intel_feeds
        first_reason_pair = intel_feeds[0]
        first_feed = first_reason_pair[0].replace("|", "\|")
        first_source = first_reason_pair[1].replace("|", "\|")
        self.indicator.intel_feed = first_feed
        self.indicator.intel_source = first_source
        

        self.indicator.intel_confidence = self.result.get("max_confidence", "-")
        nps_cat = self.result.get("nps_cat", 0)
        if self.indicator.intel_confidence == "-" and nps_cat > 0:
            self.indicator.intel_confidence = nps_cat

        self.indicator.subdomain_count = self.result.get("subdomain_count", 0)
        self.indicator.url_count = self.result.get("path_count", "-")
        self.indicator.is_in_intel = True
        
        is_inexact = self.result.get("is_inexact", False)
        self.indicator.e_list_entry = not is_inexact
        self.indicator.subdomain_only = False
        CarrierIntelLoader.previous_queries[self.indicator.candidate] = self.result


def str_to_bool(string):
    if type(string) == str:
        return True if string.lower() == "true" else False
    else:
        return string


