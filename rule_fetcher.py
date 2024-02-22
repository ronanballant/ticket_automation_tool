import csv

from config import rule_table_path


class RuleFetcher:
    def __init__(self) -> None:
        self.open_file()

    def open_file(self):
        with open(rule_table_path, "r", newline="", encoding="utf-8") as csv_file:
            file = csv.DictReader(csv_file, delimiter="\t")
            self.file = [row for row in file]
