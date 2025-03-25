import csv

from config import rule_path


class RuleFetcher:
    def __init__(self, logger) -> None:
        self.logger = logger
        try:
            self.open_file()
            self.create_rule_table()
        except Exception as e:
            self.logger.error(f"Failed to initialize RuleFetcher: {e}")
            raise

    def open_file(self):
        self.logger.info("Loading Rule-Set")
        try:
            with open(rule_path, "r", newline="", encoding="utf-8") as csv_file:
                file = csv.DictReader(csv_file, delimiter=",")
                self.file = [row for row in file]
            self.logger.info("Rule-Set loaded successfully")
        except FileNotFoundError:
            self.logger.error(f"File not found: {rule_path}")
            raise
        except csv.Error as e:
            self.logger.error(f"CSV parsing error: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error while loading Rule-Set: {e}")
            raise

    def create_rule_table(self):
        self.logger.info("Generating rule table")
        try:
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
            self.logger.info("Rule table generated successfully")
        except KeyError as e:
            self.logger.error(f"Missing expected key in CSV data: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error while generating rule table: {e}")
            raise


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
