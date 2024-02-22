from config import logger
from mongo_craden import blacklist


class EtpIntelFetcher:
    def __init__(self, entities) -> None:
        self.entities = entities
        self.fetch_intel()
        self.assign_results()

    def fetch_intel(self):
        logger.info("Generating ETP intel query")
        for entity in self.entities:
            if entity.domain[-1] == ".":
                entity.etp_domain = entity.domain
                entity.domain = entity.domain[:-1]
            else:
                entity.etp_domain = entity.domain + "."

            cursor = blacklist.find({"etp_record": entity.etp_domain})
            entity.mongo_results = [record for record in cursor]

    def assign_results(self):
        etp_domain_status_list = []

        for entity in self.entities:
            logger.info("Attributing intel to {}", entity.entity)
            if entity.mongo_results:
                for record in entity.mongo_results:
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
                    if etp_domain_status_list[0].get("filtered") is False:
                        strongest_result = etp_domain_status_list[0]
                    else:
                        self.no_intel(entity)

                entity.intel_category = strongest_result.get("category", "-")
                entity.intel_source = strongest_result.get("source_feed", "-")
                entity.intel_description = strongest_result.get("description", "-")
                entity.is_filtered = str_to_bool(
                    strongest_result.get("filtered", False)
                )
                entity.filter_reason = strongest_result.get("filter_reason", "-")
                entity.intel_threat_id = strongest_result.get("threat_id", "-")
                entity.intel_list_id = strongest_result.get("list_id", "-")
                entity.intel_category_strength = (
                    "strong" if entity.intel_list_id in [1, 2, 3] else "weak"
                )
                entity.intel_threat_keywords = strongest_result.get(
                    "threat_keywords", "-"
                )
                entity.is_in_intel = True
            else:
                self.no_intel(entity)

    def no_intel(self, entity):
        entity.intel_category = "-"
        entity.intel_source = "-"
        entity.intel_description = "-"
        entity.intel_is_filtered = "-"
        entity.intel_filter_reason = "-"
        entity.intel_threat_id = "-"
        entity.intel_list_id = "-"
        entity.intel_threat_keywords = "-"
        entity.intel_is_in_intel = False

    # if etp_domain_status_list:
    #     self.result = {"ETP Intel": [strongest_result]}
    #     logger.info(f"Domain exists in ETP Intel: {domain}")
    #     return True, result
    # else:
    #     result = "Domain doesn't exist in ETP Intel"
    #     logger.info(f"Domain doesn't exist in ETP Intel: {domain}")
    #     return False, result

    # def assign_results(self):
    #     for entity in self.entities:
    #         result = self.results.get(entity.domain)
    #         if result:
    #             entity.intel_feed = result.get('intel_feed')
    #             entity.intel_confidence = result.get('intel_confidence')
    #             if entity.intel_confidence:
    #                 entity.intel_confidence = float(entity.intel_confidence)
    #             entity.intel_source = result.get('intel_source')
    #             entity.is_in_intel = result.get('is_in_intel')


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
