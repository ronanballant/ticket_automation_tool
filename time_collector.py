import json
import os
import socket
from datetime import datetime

import requests

from config import (dashboard_tickets, etp_processed_tickets_file, get_logger,
                    jira_search_api, project_folder,
                    sps_processed_tickets_file)
from key_handler import KeyHandler
from ticket import Ticket

logger = get_logger("logs_dashboard_process.txt")
cert_path = os.path.join(project_folder, ".dashboard_personal_crt.crt")
key_path = os.path.join(project_folder, ".dashboard_personal_key.key")
ssh_key_path = os.path.join(project_folder, ".dashboard_ssh_key")



class TicketHandler:
    def __init__(self, ticket_data_file) -> None:
        self.ticket_data_file = ticket_data_file

    def open_ticket_data(self):
        with open(dashboard_tickets, "r") as file:
            self.ticket_data = json.load(file)

    def get_ticket_details(self):
        self.queue = self.ticket.get('queue', None)
        self.ticket_id = self.ticket.get('ticket_id', None)
        self.ticket_resolved = self.ticket.get('ticket_resolved', None)
        self.time_to_resolution = self.ticket.get('time_to_resolution', None)
        self.creation_time = self.ticket.get('creation_time', None)

    def check_required_data(self):
        self.get_time_to_resolution = False
        self.get_time_to_response = False
        
        if not self.time_to_resolution or self.time_to_resolution == "-":
            self.get_time_to_resolution = True

    def fetch_jira_ticket(self):
        try:
            if self.queue.lower() == "sps":
                jql_query = f'project="ReCat Sec Ops Requests" AND issue = "{self.ticket_id}"'

            if self.queue.lower() == "etp":
                jql_query = f'project="Enterprise Tier 3 Escalation Support" AND issue = "{self.ticket_id}"'
            
            params = {"jql": jql_query, "maxResults": 100}
            self.req = requests.get(
                jira_search_api,
                params=params,
                cert=(cert_path, key_path),
                verify=False,
            )
        except Exception as e:
            logger.error(f"JIRA ticket API Failed: {e}")
            raise

    def parse_jira_ticket_data(self):
        try:
            if self.req.status_code == 200:
                logger.info(f"{self.ticket_id} Retrieved")
                logger.info("Parsing ticket")
                result_dict = json.loads(self.req.text)
                issues = result_dict.get("issues")
                self.tickets = {}
                if issues:
                    for entry in issues:
                        fields = entry.get("fields")
                        if fields:
                            self.resolution_date = fields.get("resolutiondate")
        except:
            pass

    def update_resolution_time(self):
        if self.resolution_date:
            res_date = datetime.fromisoformat(self.resolution_date)
            create_date = datetime.fromisoformat(self.creation_time)

            time_to_resolution = res_date - create_date
            self.ticket["time_to_resolution"] = time_to_resolution.total_seconds()  

    def save_new_ticket_data(self):
        with open("/Users/rballant/Documents/ticket_dashboard_data_new.json", "w") as file:
            json.dump(self.ticket_data, file, indent=4)

if __name__ == "__main__":
    server_name = socket.gethostname()
    if "muc" in server_name:
        queue = "SPS"
        processed_tickets_file = sps_processed_tickets_file
    elif server_name == "prod-galaxy-t4tools.dfw02.corp.akamai.com":
        queue = "ETP"
        processed_tickets_file = etp_processed_tickets_file
        
    key_handler = KeyHandler(logger, cert_path, key_path, ssh_key_path)
    key_handler.get_key_names()
    key_handler.get_personal_keys()

    ticket_handler = TicketHandler(dashboard_tickets)
    ticket_handler.open_ticket_data()
    for ticket in ticket_handler.ticket_data:
        ticket_handler.ticket = ticket
        ticket_handler.get_ticket_details()
        ticket_handler.check_required_data()
        if ticket_handler.get_time_to_resolution is True:
            ticket_handler.fetch_jira_ticket()
            ticket_handler.parse_jira_ticket_data()
            ticket_handler.update_resolution_time()

ticket_handler.save_new_ticket_data()

        

