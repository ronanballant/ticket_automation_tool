import csv
import json
import time

from config import logger
from ticket import Ticket


class SummaryCreator:
    def __init__(self, tickets_in_progress_file, open_summary_tickets_file) -> None:
        self.tickets_in_progress_file = tickets_in_progress_file
        self.open_summary_tickets_file = open_summary_tickets_file

    def load_ticket_data(self):
        with open(self.tickets_in_progress_file, "r") as file:
            if file:
                self.ticket_data = json.load(file)

    def create_tickets(self):
        for ticket in self.ticket_data:
            Ticket.from_dict(ticket)

    def clear_tickets(self):
        with open(self.tickets_in_progress_file, "w") as file:
            json.dump([], file, indent=4)

    def archive_tickets(self):
        self.archive_filename = self.tickets_in_progress_file[:-5] + "_" + str(int(time.time())) + ".json"
        tickets_dicts = []
        with open(self.archive_filename, "w") as file:
            for ticket in Ticket.all_tickets:
                ticket_dict = ticket.to_dict()
                tickets_dicts.append(ticket_dict)
            
            json.dump(tickets_dicts, file, indent=4)

    def save_open_summary_ticket(self, summary_ticket):
        with open(self.open_summary_tickets_file, "a+") as file:
            writer = csv.writer(file)
            writer.writerow([summary_ticket])
