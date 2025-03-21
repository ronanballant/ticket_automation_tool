import ast
import subprocess

from config import (destination_ip, destination_username, intel_fetcher_path,
                    jump_host_ip, jump_host_username, logger, private_key_path)


class SPSIntelFetcher:
    previous_queries = {}

    def __init__(self, indicator) -> None:
        self.indicator = indicator
        self.results = {}

    def read_previous_queries(self):
        try:
            self.results[self.indicator.candidate] = SPSIntelFetcher.previous_queries.get(
                self.indicator.candidate, None
            )
        except Exception as e:
            print(f"Failed to read previous Intel query: {e}")
            logger.error(f"Failed to read previous Intel query: {e}")
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
            logger.info(f"SPS Intel query sent for {self.indicator.candidate}")
            self.results = ast.literal_eval(result.stdout)
            SPSIntelFetcher.previous_queries[self.indicator.candidate] = self.results
        except Exception as e:
            print(f"Error querying SPS intel: {e}")
            logger.error(f"Error querying SPS intel: {e}")
            self.results = None

    def assign_results(self):
        try:
            logger.info(f"Attributing intel to {self.indicator.fqdn}")
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
            print(f"Error attributing SPS intel: {e}")
            logger.error(f"Error attributing SPS intel: {e}")
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
        SPSIntelFetcher.previous_queries[self.indicator.candidate] = {}

def str_to_bool(string):
    if type(string) == str:
        return True if string.lower() == "true" else False
    else:
        return string
