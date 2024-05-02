import csv
import os


from config import logger, results_file_path


class TicketResolver:
    DAYS_SINCE_CREATION = 30  # days since creation

    def __init__(self, entity, rules, file_time) -> None:
        self.entity = entity
        self.rules = rules
        self.file_path = results_file_path + f"{file_time}_results.csv"
        self.prepare_fp_rule_query()
        self.match_rule()
        self.write_resolutions()

    def prepare_fp_rule_query(self):
        logger.info("Preparing data for rule matching")
        if self.entity.queue == "SPS":
            self.entity.is_filtered = "-"
            self.entity.intel_category_strength = "-"

            if self.entity.is_in_intel is True:
                if self.entity.intel_confidence and self.entity.intel_confidence != "-":
                    if self.entity.intel_confidence >= 0.90:
                        self.entity.confidence_level = 5
                    elif self.entity.intel_confidence >= 0.80:
                        self.entity.confidence_level = 4
                    elif self.entity.intel_confidence >= 0.70:
                        self.entity.confidence_level = 3
                    elif self.entity.intel_confidence >= 0.60:
                        self.entity.confidence_level = 2
                    elif self.entity.intel_confidence >= 0.50:
                        self.entity.confidence_level = 1
                    else:
                        self.entity.confidence_level = "-"
                else:
                    self.entity.confidence_level = "-"
        else:
            self.entity.confidence_level = "-"
            self.entity.intel_feed = "-"
            self.entity.intel_confidence = "-"
            self.entity.intel_source = "-"
            self.entity.e_list_entry = False

        if self.entity.has_data:
            if self.entity.days_since_creation > TicketResolver.DAYS_SINCE_CREATION:
                self.entity.domain_age = "old"
            else:
                self.entity.domain_age = "new"
        else:
            self.entity.domain_age = "-"

    def match_rule(self):
        if self.entity.has_data is True:
            if int(self.entity.subdomain_count) <= 3:
                if self.entity.e_list_entry is False:
                    logger.info(f"Matching {self.entity.entity} data against rule set")
                    group = self.rules.get(self.entity.queue)
                    type_match = group.get(self.entity.ticket_type)
                    is_in_intel = type_match.get(self.entity.is_in_intel)
                    is_filtered = is_in_intel.get(self.entity.is_filtered)
                    category_strength = is_filtered.get(self.entity.intel_category_strength)
                    age = category_strength.get(self.entity.domain_age)

                    if self.entity.positives != "-":
                        age.pop("-", None)
                        min_positives = {}
                        max_positives = {}
                        for key, item_value in age.items():
                            if int(key) <= self.entity.positives:
                                new_values = {
                                    k: value for k, value in item_value.items()
                                }
                                min_positives = merge_dicts(min_positives, new_values)

                        for key, item_value in min_positives.items():
                            if int(key) >= self.entity.positives:
                                new_values = {
                                    key: value for key, value in item_value.items()
                                }
                                max_positives = merge_dicts(max_positives, new_values)
                    else:
                        min_positives = age.get(self.entity.positives)
                        max_positives = min_positives.get(self.entity.positives)

                    if self.entity.confidence_level != "-":
                        min_confidence = {}
                        match = {}
                        for key, item_value in max_positives.items():
                            if int(key) <= self.entity.confidence_level:
                                new_values = {
                                    key: value for key, value in item_value.items()
                                }
                                min_confidence = merge_dicts(min_confidence, new_values)

                        for key, item_value in min_confidence.items():
                            if int(key) >= self.entity.confidence_level:
                                new_values = {
                                    key: value for key, value in item_value.items()
                                }
                                match.update(new_values)
                    else:
                        min_confidence = max_positives.get(self.entity.confidence_level)
                        match = min_confidence.get(self.entity.confidence_level)

                    self.entity.resolution = match["verdict"]
                    response = match["response"].replace("\\n", "\n")
                    self.entity.response = response
                else:
                    self.entity.resolution = "In Progress"
                    self.entity.response = f"Entity in exact match lists with {self.entity.url_count} paths"
            else:
                self.entity.resolution = "In Progress"
                self.entity.response = f"Entity has {self.entity.subdomain_count} subdomains in the intel"
        else:
            logger.info("No data to match against rule set")
            self.entity.resolution = "In Progress"
            self.entity.response = "No VT data"

    def write_resolutions(self):
        if not os.path.exists(results_file_path):
            os.makedirs(results_file_path)
        
        try:
            logger.info(f"Writing resolutions to {self.file_path}")
            with open(self.file_path, mode="a", newline="") as file:
                csv_writer = csv.writer(file)

                if self.entity.has_data:
                    csv_writer.writerow(
                        [
                            self.entity.ticket_id,
                            self.entity.ticket_type,
                            self.entity.domain,
                            self.entity.positives,
                            self.entity.last_seen,
                            self.entity.categories,
                            self.entity.resolution,
                            self.entity.response,
                        ]
                    )
                else:
                    csv_writer.writerow(
                        [
                            self.entity.ticket_id,
                            self.entity.ticket_type,
                            self.entity.domain,
                            None,
                            None,
                            None,
                            self.entity.resolution,
                            self.entity.response,
                        ]
                    )
                # add webroot
        except Exception as e:
            logger.error(f"Error writing to {self.file_path}. Error: {e}")

def merge_dicts(dict1, dict2):
    for key, value in dict2.items():
        if key in dict1:
            if isinstance(dict1[key], dict) and isinstance(value, dict):
                merge_dicts(dict1[key], value) 
            else:
                dict1[key] += value 
        else:
            dict1[key] = value
    return dict1