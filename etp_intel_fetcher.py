import ast
import csv

from config import etp_intel_file_path, logger
from typing import List

class ETPIntelFetcher:
    previous_queries = {}

    def __init__(self, indicator, mongo_connection) -> None:
        self.indicator = indicator
        self.mongo_connection = mongo_connection
        self.attributes_assigned: bool = False
        self.intel_category: str = ""
        self.intel_source: List[str] = []
        self.intel_description: str = ""
        self.is_filtered: bool = False
        self.filter_reason: List[str] = []
        self.intel_threat_id: int = None
        self.intel_list_id: int = None
        self.intel_threat_keywords: List[str] = []
        self.intel_category_strength: str = ""
        self.is_in_intel: bool = False
        self.subdomain_count: int = None
        self.etp_fqdn: str = ""
        self.subdomain_only: bool = False
        self.previous_intel = None

    def load_previous_intel(cls):
        logger.info("Reading stored intel file")
        results = {}
        with open(etp_intel_file_path, mode="r", newline="") as file:
            reader = csv.reader(file)
            for row in reader:
                results[row[0]] = {
                    "intel_category": row[1],
                    "intel_source": [row[2]],
                    "intel_description": [row[3]],
                    "is_filtered": str_to_bool(row[4]),
                    "filter_reason": ast.literal_eval(row[5]) if row[5] else [row[5]],
                    "intel_threat_id": int(row[6]) if row[6].isdigit() else '-',
                    "intel_list_id": int(row[7]) if row[7].isdigit() else '-',
                    "intel_threat_keywords": ast.literal_eval(row[8]),
                    "intel_category_strength": row[9],
                    "is_in_intel": str_to_bool(row[10]),
                    "subdomain_count": int(row[11]) if row[11].isdigit() else '-',
                    "etp_fqdn": row[12],
                    "subdomain_only": str_to_bool(row[13]),
                }

        cls.previous_queries = results

    def read_previous_queries(self):
        try:
            self.previous_intel = self.previous_queries.get(
                self.indicator.candidate, None
            )
        except Exception as e:
            print(f"Failed to read previous Intel query: {e}")
            logger.error(f"Failed to read previous Intel query: {e}")
            raise

    def query_intel(self):
        self.read_previous_queries()

        if self.previous_intel:
            self.indicator.intel_category = self.previous_intel.get("intel_category")
            self.indicator.intel_source = self.previous_intel.get("intel_source")
            self.indicator.intel_source_list = self.previous_intel.get("intel_source")
            self.indicator.intel_description = self.previous_intel.get("intel_description")
            self.indicator.is_filtered = self.previous_intel.get("is_filtered")
            self.indicator.filter_reason = self.previous_intel.get("filter_reason")
            self.indicator.intel_threat_id = self.previous_intel.get("intel_threat_id")
            self.indicator.intel_list_id = self.previous_intel.get("intel_list_id")
            self.indicator.intel_threat_keywords = self.previous_intel.get("intel_threat_keywords")
            self.indicator.intel_category_strength = self.previous_intel.get("intel_category_strength")
            self.indicator.is_in_intel = self.previous_intel.get("is_in_intel")
            self.indicator.subdomain_count = self.previous_intel.get("subdomain_count")
            self.indicator.etp_fqdn = self.previous_intel.get("etp_fqdn")
            self.indicator.subdomain_only = self.previous_intel.get("subdomain_only")
            self.attributes_assigned = True
        else:
            if self.indicator.candidate[-1] == ".":
                self.indicator.etp_candidate = self.indicator.candidate
                self.indicator.candidate = self.indicator.candidate[:-1]
            else:
                self.indicator.etp_candidate = self.indicator.candidate + "."

            try:
                cursor = self.mongo_connection.blacklist.find(
                    {"etp_record": self.indicator.etp_candidate}
                )
                self.indicator.mongo_results = [record for record in cursor]

                sudomain_pattern = f".*.{self.indicator.etp_candidate}"
                cursor = self.mongo_connection.blacklist.find(
                    {"#data": {"$regex": sudomain_pattern}}
                )
                subdomain_results = [record for record in cursor]
                self.indicator.subdomain_count = len(subdomain_results)

                if (
                    len(self.indicator.mongo_results) == 0
                    and self.indicator.subdomain_count > 0
                ):
                    self.indicator.subdomain_only = True
                else:
                    self.indicator.subdomain_only = False

                ETPIntelFetcher.previous_queries[self.indicator.etp_candidate] = {
                    "mongo_results": self.indicator.mongo_results,
                    "subdomain_only": self.indicator.subdomain_only,
                    "subdomain_count": self.indicator.subdomain_count,
                }
            except Exception as e:
                print(f"Error querying ETP intel: {e}")
                logger.error(f"Error querying ETP intel: {e}")
                self.no_intel()

    def assign_results(self):
        if self.attributes_assigned is False:
            sources = []
            etp_fqdn_status_list = []
            self.indicator.intel_source_list = []
            logger.info(f"Attributing intel to {self.indicator.fqdn}")
            if self.indicator.mongo_results:
                for record in self.indicator.mongo_results:
                    sources.append(", ".join(record.get("source_feed", [])))
                    etp_fqdn_status = {
                        "intel_category": record.get("category", ""),
                        "intel_source": ", ".join(record.get("source_feed", [])),
                        "intel_description": ", ".join(record.get("description", "")),
                        "is_filtered": record.get("filtered", False),
                        "filter_reason": record.get("filter_reason", ""),
                        "intel_threat_id": record.get("threat_id", ""),
                        "intel_list_id": record.get("list_id", ""),
                        "intel_threat_keywords": record.get("threat_keywords", []),
                    }
                    etp_fqdn_status["category_level"] = get_category_level(
                        etp_fqdn_status["intel_list_id"]
                    )
                    etp_fqdn_status_list.append(etp_fqdn_status)

                etp_fqdn_status_list.sort(
                    key=lambda x: (
                        x.get("is_filtered", False),
                        x.get("intel_list_id") not in [1, 2, 3],
                        x.get("intel_list_id", 0),
                    )
                )

                self.indicator.intel_source_list = list(set(sources))
                if etp_fqdn_status_list:
                    strongest_result = etp_fqdn_status_list[0]

                    self.indicator.intel_category = strongest_result.get("intel_category", "-")
                    self.indicator.intel_source = strongest_result.get("intel_source", "-")
                    self.indicator.is_internal = is_internal_source(self.indicator.intel_source)
                    self.indicator.is_in_man_bl = is_in_man_bl(", ".join(sources))
                    self.indicator.intel_description = strongest_result.get("intel_description", "-")
                    self.indicator.is_filtered = str_to_bool(
                        strongest_result.get("is_filtered", "-")
                    )
                    self.indicator.filter_reason = strongest_result.get("filter_reason", "-")
                    self.indicator.intel_threat_id = strongest_result.get("intel_threat_id", "-")
                    self.indicator.intel_list_id = strongest_result.get("intel_list_id", "-")
                    if self.indicator.intel_list_id != "-":
                        self.indicator.intel_category_strength = (
                            "strong" if self.indicator.intel_list_id in [1, 2, 3] else "weak"
                        )
                    else:
                        self.indicator.intel_category_strength = "-"
                    self.indicator.intel_threat_keywords = strongest_result.get(
                        "intel_threat_keywords", "-"
                    )
                    self.indicator.is_in_intel = (
                        True if self.indicator.intel_category != "-" else False
                    )
                else:
                    self.no_intel()
            else:
                self.no_intel()

    def no_intel(self):
        self.indicator.intel_category = "-"
        self.indicator.intel_source = "-"
        self.indicator.intel_source_list = []
        self.indicator.intel_description = "-"
        self.indicator.is_filtered = "-"
        self.indicator.filter_reason = "-"
        self.indicator.intel_threat_id = "-"
        self.indicator.intel_list_id = "-"
        self.indicator.intel_threat_keywords = "-"
        self.indicator.intel_category_strength = "-"
        self.indicator.is_in_intel = False
        self.indicator.subdomain_count = 0
        self.indicator.subdomain_only = False
        self.indicator.is_internal = False

        ETPIntelFetcher.previous_queries[self.indicator.fqdn] = {}

    def write_intel_file(self):
        with open(etp_intel_file_path, mode="a", newline="") as file:
            csv_writer = csv.writer(file)
            logger.info(f"Writing {self.indicator.fqdn} to intel file")
            csv_writer.writerow(
                [
                    self.indicator.fqdn,
                    self.indicator.intel_category,
                    self.indicator.intel_source,
                    self.indicator.intel_description,
                    self.indicator.is_filtered,
                    self.indicator.filter_reason,
                    self.indicator.intel_threat_id,
                    self.indicator.intel_list_id,
                    self.indicator.intel_threat_keywords,
                    self.indicator.intel_category_strength,
                    self.indicator.is_in_intel,
                    self.indicator.subdomain_count,
                    self.indicator.etp_fqdn,
                    self.indicator.subdomain_only,
                ]
            )

def get_category_level(list_id):
    if list_id in [1, 2, 3]:
        category_level = "strong"
    else:
        category_level = "weak"

    return category_level


def str_to_bool(string):
    if type(string) == str:
        return True if string.lower() == "true" else False
    else:
        return string


def is_internal_source(source):
    if any(substring in source.lower() for substring in ["nom", "etp", "man"]):
        return True
    else:
        return False


def is_in_man_bl(source):
    if "manual" in source.lower():
        return True
    else:
        return False
