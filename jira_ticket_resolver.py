import csv

from config import logger, results_file_path
from rule_fetcher import RuleFetcher


class TicketResolver:
    DAYS_SINCE_CREATION = 30  # days since creation

    def __init__(self, entity, file_time) -> None:
        self.entity = entity
        self.file = RuleFetcher().file
        self.file_path = results_file_path + f"{file_time}_results.csv"
        self.prepare_fp_rule_query()
        self.create_rule_table()
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

    def create_rule_table(self):
        logger.info("Generating rule sets")
        transformed_data = {}

        for row in self.file:
            queue = row["group"]
            rule_type = row["type"]
            is_in_intel = str_to_bool(row["is_in_intel"])
            is_filtered = str_to_bool(row["is_filtered"])
            category_strength = row["category_strength"]
            age = row["age"]
            min_positives = row["min_positives"]
            max_positives = row["max_positives"]
            min_confidence = row["min_confidence"]
            max_confidence = row["max_confidence"]
            verdict = row["verdict"]
            response = row["response"]

            rule_dict = {"verdict": verdict, "response": response}

            if queue not in transformed_data:
                transformed_data[queue] = {}
            if rule_type not in transformed_data[queue]:
                transformed_data[queue][rule_type] = {}
            if is_in_intel not in transformed_data[queue][rule_type]:
                transformed_data[queue][rule_type][is_in_intel] = {}
            if is_filtered not in transformed_data[queue][rule_type][is_in_intel]:
                transformed_data[queue][rule_type][is_in_intel][is_filtered] = {}
            if (
                category_strength
                not in transformed_data[queue][rule_type][is_in_intel][is_filtered]
            ):
                transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ] = {}
            if (
                age
                not in transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ]
            ):
                transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age] = {}
            if (
                min_positives
                not in transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age]
            ):
                transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age][min_positives] = {}
            if (
                max_positives
                not in transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age][min_positives]
            ):
                transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age][min_positives][max_positives] = {}
            if (
                min_confidence
                not in transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age][min_positives][max_positives]
            ):
                transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age][min_positives][max_positives][min_confidence] = {}
            if (
                max_confidence
                not in transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age][min_positives][max_positives][min_confidence]
            ):
                transformed_data[queue][rule_type][is_in_intel][is_filtered][
                    category_strength
                ][age][min_positives][max_positives][min_confidence][
                    max_confidence
                ] = rule_dict

        self.rules = transformed_data

    def match_rule(self):
        if self.entity.has_data is True:
            if self.entity.e_list_entry is False:
                logger.info("Matching data against rule set")
                group = self.rules.get(self.entity.queue, self.rules.get("-"))
                type_match = group.get(self.entity.ticket_type, group.get("-"))
                is_in_intel = type_match.get(
                    self.entity.is_in_intel, type_match.get("-")
                )
                is_filtered = is_in_intel.get(
                    self.entity.is_filtered, is_in_intel.get("-")
                )
                category_strength = is_filtered.get(
                    self.entity.intel_category_strength, is_filtered.get("-")
                )
                age = category_strength.get(
                    self.entity.domain_age, category_strength.get("-")
                )

                if self.entity.positives != "-":
                    min_positives = {}
                    max_positives = {}
                    for key, item_value in age.items():
                        if int(key) <= self.entity.positives:
                            new_values = {
                                key: value for key, value in item_value.items()
                            }
                            min_positives.update(new_values)

                    for key, item_value in min_positives.items():
                        if int(key) >= self.entity.positives:
                            new_values = {
                                key: value for key, value in item_value.items()
                            }
                            max_positives.update(new_values)
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
                            min_confidence.update(new_values)

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
                self.entity.response = "Entity in exact match lists"
        else:
            logger.info("No data to match against rule set")
            self.entity.resolution = "In Progress"
            self.entity.response = "No VT data"

    def write_resolutions(self):
        try:
            logger.info("Writing resolutions to {}", self.file_path)
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
            logger.error("Error writing to {}. Error: {}", self.file_path, e)


def str_to_bool(string):
    if type(string) == str:
        if string.lower() == "true":
            return True
        elif string.lower() == "-":
            return string
        else:
            return False
    else:
        return string
