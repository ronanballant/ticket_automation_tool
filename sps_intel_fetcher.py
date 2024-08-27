import ast
import csv
import subprocess

from config import (destination_ip, destination_username, intel_fetcher_path,
                    sps_intel_file_path, jump_host_ip, jump_host_username, logger,
                    private_key_path)


class SpsIntelFetcher:
    previous_queries = {}

    def __init__(self, entity) -> None:
        self.entity = entity
        self.fetch_intel()
        self.assign_results()
        # self.write_intel_file()
        # self.open_intel()

    def read_previous_queries(self):
        try:
            self.previous_intel = SpsIntelFetcher.previous_queries.get(self.entity.domain)
        except Exception as e:
            print(f"Failed to read previous Intel query: {e}")
            logger.error(f"Failed to read previous Intel query: {e}")
            raise

    def fetch_intel(self):
        self.read_previous_queries()

        if self.previous_intel:
            self.results = self.previous_intel
        else:
            ssh_command = [
                "ssh",
                "-i",
                private_key_path,
                "-J {}@{}".format(jump_host_username, jump_host_ip),
                "{}@{}".format(destination_username, destination_ip),
                "python3 {} -d '{}'".format(intel_fetcher_path, self.entity.domain)
            ]

            try:
                result = subprocess.run(
                    ssh_command, check=True, capture_output=True, text=True
                )
                logger.info(f"SPS Intel query sent for {self.entity.domain}")
                self.results = ast.literal_eval(result.stdout)
                SpsIntelFetcher.previous_queries[self.entity.domain] = self.results
            except Exception as e:
                print(f"Error querying SPS intel: {e}")
                logger.error(f"Error querying SPS intel: {e}")
                self.results = None

    def assign_results(self):
        try:
            logger.info(f"Attributing intel to {self.entity.domain}")
            result = self.results.get(self.entity.domain)
            if result:
                self.entity.is_in_intel = str_to_bool(result.get("is_in_intel", "-"))
                self.entity.subdomain_only = str_to_bool(result.get("subdomain_only"))
                if self.entity.is_in_intel is True:
                    self.entity.intel_feed = result.get("intel_feed", "-")
                    self.entity.intel_confidence = result.get("intel_confidence", "-")
                    if self.entity.intel_confidence != "-":
                        if self.entity.intel_confidence:
                            self.entity.intel_confidence = float(self.entity.intel_confidence)
                    self.entity.subdomain_count = result.get("subdomain_count", 0)
                    self.entity.url_count = result.get("url_count", 0)
                    self.entity.intel_source = result.get("intel_source", "-").replace("|", "/")
                    self.entity.e_list_entry = str_to_bool(result.get("e_list_entry", False))
                    
                else:
                    self.no_intel()
            else:
                self.no_intel()
        except Exception as e:
            print(f"Error attributing SPS intel: {e}")
            logger.error(f"Error attributing SPS intel: {e}")
            raise

    def no_intel(self):
        self.entity.intel_feed = "-"
        self.entity.intel_confidence = "-"
        self.entity.intel_source = "-"
        self.entity.confidence_level = "-"
        self.entity.subdomain_count = 0
        self.entity.url_count = 0 
        self.entity.is_in_intel = False
        self.entity.e_list_entry = False
        self.entity.subdomain_only = False
        SpsIntelFetcher.previous_queries[self.entity.domain] = {}

    def write_intel_file(self):
        try:
            with open(sps_intel_file_path, mode="w", newline="") as file:
                csv_writer = csv.writer(file)
                for entity in self.entities:
                    logger.info(f"Writing {entity.entity} to intel file")
                    csv_writer.writerow(
                        [
                            entity.domain,
                            entity.intel_feed,
                            entity.intel_confidence,
                            entity.intel_source,
                            entity.is_in_intel,
                            entity.e_list_entry,
                            entity.subdomain_count,
                            entity.url_count,
                            entity.subdomain_only,
                        ]
                    )
        except Exception as e:
            print(f"Error writing SPS intel to {sps_intel_file_path}: {e}")
            logger.error(f"Error writing SPS intel to {sps_intel_file_path}: {e}")

    def open_intel(self):
        try:
            logger.info("Reading stored intel file")
            with open(sps_intel_file_path, mode="r", newline="") as file:
                reader = csv.reader(file)
                self.results = {}
                for row in reader:
                    self.results[row[0]] = {
                        "intel_feed": row[1],
                        "intel_confidence": row[2],
                        "intel_source": row[3],
                        "is_in_intel": row[4],
                        "e_list_entry": row[5],
                        "subdomain_count": row[6],
                        "url_count": row[7],
                        "subdomain_only": row[8],
                    }

                self.assign_results()
        except Exception as e:
            print(f"Error opening SPS intel at {sps_intel_file_path}: {e}")
            logger.error(f"Error opening SPS intel at {sps_intel_file_path}: {e}")



def str_to_bool(string):
    if type(string) == str:
        return True if string.lower() == "true" else False
    else:
        return string
