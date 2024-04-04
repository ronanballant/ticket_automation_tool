import ast
import csv
import subprocess

from config import (destination_ip, destination_username, intel_fetcher_path,
                    intel_file_path, jump_host_ip, jump_host_username, logger,
                    private_key_path)


class SpsIntelFetcher:
    def __init__(self, entities) -> None:
        self.entities = entities
        self.fetch_intel()
        self.assign_results()
        self.write_intel_file()
        # self.open_intel()

    def fetch_intel(self):
        domain_list = [entity.domain for entity in self.entities]
        domains = ",".join(domain_list)

        ssh_command = [
            "ssh",
            "-i",
            private_key_path,
            "-J {}@{}".format(jump_host_username, jump_host_ip),
            "{}@{}".format(destination_username, destination_ip),
            "python3 {} -d '{}'".format(intel_fetcher_path, domains),
        ]

        try:
            result = subprocess.run(
                ssh_command, check=True, capture_output=True, text=True
            )
            logger.info("SPS Intel query sent")
            self.results = ast.literal_eval(result.stdout)
        except subprocess.CalledProcessError as e:
            logger.error("Error querying SPS intel:", e)
            self.results = None

    def assign_results(self):
        for entity in self.entities:
            logger.info("Attributing intel to {}", entity.entity)
            result = self.results.get(entity.domain)
            if result:
                entity.is_in_intel = str_to_bool(result.get("is_in_intel", False))
                if entity.is_in_intel is True:
                    entity.intel_feed = result.get("intel_feed", "-")
                    entity.intel_confidence = result.get("intel_confidence", "-")
                    if entity.intel_confidence != "-":
                        if entity.intel_confidence:
                            entity.intel_confidence = float(entity.intel_confidence)
                    entity.subdomain_count = result.get("subdomain_count", 0)
                    entity.url_count = result.get("url_count", 0)
                    entity.intel_source = result.get("intel_source", "-")
                    entity.e_list_entry = str_to_bool(result.get("e_list_entry", False))
                else:
                    self.no_intel(entity)

    def no_intel(self, entity):
        entity.intel_feed = "-"
        entity.intel_confidence = "-"
        entity.intel_source = "-"
        entity.confidence_level = "-"
        entity.subdomain_count = 0
        entity.url_count = 0 
        entity.is_in_intel = False
        entity.e_list_entry = False

    def write_intel_file(self):
        with open("intel_file.csv", mode="w", newline="") as file:
            csv_writer = csv.writer(file)
            for entity in self.entities:
                logger.info("Writing {} to intel file", entity.entity)
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
                    ]
                )

    def open_intel(self):
        logger.info("Reading stored intel file")
        with open(intel_file_path, mode="r", newline="") as file:
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
                }

            self.assign_results()


def str_to_bool(string):
    if type(string) == str:
        return True if string.lower() == "true" else False
    else:
        return string
