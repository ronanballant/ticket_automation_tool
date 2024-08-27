from config import logger
# from mongo_craden import blacklist

from config import etp_intel_file_path
import csv

class EtpIntelFetcher:
    previous_queries = {}

    def __init__(self, entity, mongo_connection) -> None:
        self.entity = entity
        self.mongo_connection = mongo_connection
        self.fetch_intel()
        self.assign_results()
        # self.write_intel_file()
        # self.open_intel()

    def read_previous_queries(self):
        try:
            self.previous_intel = EtpIntelFetcher.previous_queries.get(self.entity.domain)
        except Exception as e:
            print(f"Failed to read previous Intel query: {e}")
            logger.error(f"Failed to read previous Intel query: {e}")
            raise

    def fetch_intel(self):
        self.read_previous_queries()

        if self.previous_intel:
            self.entity.mongo_results = self.previous_intel.get("mongo_results")
            self.entity.subdomain_only = self.previous_intel.get("subdomain_only")
            self.entity.subdomain_count = self.previous_intel.get("subdomain_count")
        else:
            if self.entity.domain[-1] == ".":
                self.entity.etp_domain = self.entity.domain
                self.entity.domain = self.entity.domain[:-1]
            else:
                self.entity.etp_domain = self.entity.domain + "."
                
            try:
                cursor = self.mongo_connection.blacklist.find({"etp_record": self.entity.etp_domain})
                self.entity.mongo_results = [record for record in cursor]
                
                sudomain_pattern = f".*.{self.entity.etp_domain}"
                cursor = self.mongo_connection.blacklist.find({"#data": {"$regex": sudomain_pattern}})
                subdomain_results = [record for record in cursor]
                self.entity.subdomain_count = len(subdomain_results)

                if len(self.entity.mongo_results) == 0 and self.entity.subdomain_count > 0:
                    self.entity.subdomain_only = True
                else:
                    self.entity.subdomain_only = False
                
                EtpIntelFetcher.previous_queries[self.entity.domain] = {
                    "mongo_results": self.entity.mongo_results,
                    "subdomain_only": self.entity.subdomain_only,
                    "subdomain_count": self.entity.subdomain_count,
                }
            except Exception as e:
                print(f"Error querying ETP intel: {e}")
                logger.error(f"Error querying ETP intel: {e}")
                self.no_intel()   



    # def fetch_intel(self):
    #     logger.info("Generating ETP intel query")
    #     for entity in self.entities:
    #         if entity.domain[-1] == ".":
    #             entity.etp_domain = entity.domain
    #             entity.domain = entity.domain[:-1]
    #         else:
    #             entity.etp_domain = entity.domain + "."

    #         cursor = blacklist.find({"etp_record": entity.etp_domain})
    #         entity.mongo_results = [record for record in cursor]

    #         sudomain_pattern = f".*.{entity.etp_domain}"
    #         cursor = blacklist.find({{"#data": {"$regex": sudomain_pattern}}})
    #         entity.subdomain_count = len(cursor)

    def assign_results(self):
        sources = []
        etp_domain_status_list = []
        logger.info(f"Attributing intel to {self.entity.entity}")
        if self.entity.mongo_results:
            for record in self.entity.mongo_results:
                sources.append(", ".join(record.get("source_feed", [])))
                etp_domain_status = {
                    "category": record.get("category", ""),
                    "source_feed": ", ".join(record.get("source_feed", [])),
                    "description": ", ".join(record.get("description", "")),
                    "filtered": record.get("filtered", False),
                    "filter_reason": record.get("filter_reason", ""),
                    "threat_id": record.get("threat_id", ""),
                    "list_id": record.get("list_id", ""),
                    "threat_keywords": record.get("threat_keywords", []),
                }
                etp_domain_status["category_level"] = get_category_level(
                    etp_domain_status["list_id"]
                )
                etp_domain_status_list.append(etp_domain_status)

            etp_domain_status_list.sort(
                key=lambda x: (
                    x.get("filtered", False),
                    x.get("list_id") not in [1, 2, 3],
                    x.get("list_id", 0),
                )
            )

            if etp_domain_status_list:
                strongest_result = etp_domain_status_list[0]

                self.entity.intel_category = strongest_result.get("category", "-")
                self.entity.intel_source = strongest_result.get("source_feed", "-")
                self.entity.is_internal = is_internal_source(self.entity.intel_source)
                self.entity.is_in_man_bl = is_in_man_bl(", ".join(sources))
                self.entity.intel_description = strongest_result.get("description", "-")
                self.entity.is_filtered = str_to_bool(strongest_result.get("filtered", "-"))
                self.entity.filter_reason = strongest_result.get("filter_reason", "-")
                self.entity.intel_threat_id = strongest_result.get("threat_id", "-")
                self.entity.intel_list_id = strongest_result.get("list_id", "-")
                if self.entity.intel_list_id != "-":
                    self.entity.intel_category_strength = "strong" if self.entity.intel_list_id in [1, 2, 3] else "weak"
                else:
                    self.entity.intel_category_strength = "-"
                self.entity.intel_threat_keywords = strongest_result.get("threat_keywords", "-")
                self.entity.is_in_intel = True if self.entity.intel_category != "-" else False
            else:
                self.no_intel()
        else:
            self.no_intel()

    def no_intel(self):
        self.entity.intel_category = "-"
        self.entity.intel_source = "-"
        self.entity.intel_description = "-"
        self.entity.is_filtered = False
        self.entity.filter_reason = "-"
        self.entity.intel_threat_id = "-"
        self.entity.intel_list_id = "-"
        self.entity.intel_threat_keywords = "-"
        self.entity.intel_category_strength = "-"
        self.entity.is_in_intel = False
        self.entity.subdomain_count = 0
        self.entity.subdomain_only = False
        self.entity.is_internal = False
        EtpIntelFetcher.previous_queries[self.entity.domain] = {}

    def write_intel_file(self):
        with open(etp_intel_file_path, mode="w", newline="") as file:
            csv_writer = csv.writer(file)
            for entity in self.entity:
                logger.info(f"Writing {entity.entity} to intel file")
                csv_writer.writerow(
                    [
                        entity.domain,
                        entity.intel_category,
                        entity.intel_source,
                        entity.intel_description,
                        entity.is_filtered,
                        entity.filter_reason,
                        entity.intel_threat_id,
                        entity.intel_list_id,
                        entity.intel_threat_keywords,
                        entity.intel_category_strength,
                        entity.is_in_intel,
                        entity.subdomain_count,
                        entity.etp_domain,
                        entity.subdomain_only,
                    ]
                )

    def open_intel(self):
        logger.info("Reading stored intel file")
        results = {}
        with open(etp_intel_file_path, mode="r", newline="") as file:
            reader = csv.reader(file)
            for row in reader:
                results[row[0]] = {
                    "category": row[1],
                    "source_feed": [row[2]],
                    "description": [row[3]],
                    "filtered": str_to_bool(row[4]),
                    "filter_reason": row[5],
                    "threat_id": row[6],
                    "list_id": row[7],
                    "threat_keywords": row[8],
                    "intel_category_strength": row[9],
                    "is_in_intel": str_to_bool(row[10]),
                    "subdomain_count": row[11],
                    "etp_domain": row[12],
                    "subdomain_only": str_to_bool(row[13]),
                }

        for entity in self.entity:
            result = results.get(entity.domain)
            if result:
                entity.mongo_results = [result]
                entity.subdomain_count = result.get("subdomain_count", 0)
                entity.etp_domain = result.get("etp_domain")
                entity.subdomain_only = result.get("subdomain_only")
            else:
                entity.mongo_results = []
                entity.subdomain_count = 0
                entity.etp_domain = entity.entity
                entity.subdomain_only = 'False'

        self.assign_results()


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