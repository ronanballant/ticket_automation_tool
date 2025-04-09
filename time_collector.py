import json
import os
import socket
from datetime import datetime

import requests

from config import (dashboard_ticket_file, etp_processed_tickets_file,
                    get_logger, jira_search_api, project_folder,
                    sps_processed_tickets_file)
from key_handler import KeyHandler
from ticket import Ticket

logger = get_logger("logs_dashboard_process.txt")
cert_path = os.path.join(project_folder, ".dashboard_personal_crt.crt")
key_path = os.path.join(project_folder, ".dashboard_personal_key.key")
ssh_key_path = os.path.join(project_folder, ".dashboard_ssh_key")


class TicketHandler:
    dashboard_tickets = []
    processed_tickets = []

    def __init__(self, dashboard_ticket_file, etp_processed_tickets_file, sps_processed_tickets_file) -> None:
        self.dashboard_ticket_file = dashboard_ticket_file
        self.etp_processed_tickets_file = etp_processed_tickets_file
        self.sps_processed_tickets_file = sps_processed_tickets_file
        self.processed_ticket_data = []
        self.dashboard_ticket_data = []
        self.dashboard_tickets = []
        self.processed_tickets = []

    def load_ticket_data(self, ticket_file):
        logger.info("Loading ticket data from %s", ticket_file)
        with open(ticket_file, "r") as file:
            return json.load(file)

    def create_tickets(self, ticket_data):
        logger.info("Creating tickets")
        new_tickets = []
        for ticket in ticket_data:
            ticket.pop('ticket_responses', None)
            ticket.pop('comment', None)
            new_ticket = Ticket.from_dict(ticket, logger)
            new_tickets.append(new_ticket)

        return new_tickets

    def check_required_data(self):
        logger.info("Checking required data")
        self.get_time_to_resolution = False
        self.get_time_to_response = False
        
        if not self.ticket.time_to_resolution or self.ticket.time_to_resolution == "-":
            logger.info("Time to resolution required: %s", self.ticket.time_to_resolution)
            self.get_time_to_resolution = True

    def fetch_jira_ticket(self):
        logger.info("Fetching JIRA ticket %s", self.ticket.ticket_id)
        try:
            if self.ticket.queue.lower() == "sps":
                jql_query = f'project="ReCat Sec Ops Requests" AND issue = "{self.ticket.ticket_id}"'

            if self.ticket.queue.lower() == "etp":
                jql_query = f'project="Enterprise Tier 3 Escalation Support" AND issue = "{self.ticket.ticket_id}"'
            
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
                logger.info(f"{self.ticket.ticket_id} Retrieved")
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
        logger.info("Updating time to resolution for %s", self.ticket.ticket_id)
        self.resolution_date_updated = False
        if self.resolution_date:
            logger.info("Resolution date found %s", self.resolution_date)
            iso_str = self.resolution_date
            if iso_str.endswith('+0000') or iso_str.endswith('-0000'):
                iso_str = iso_str[:-5] + iso_str[-5:-2] + ":" + iso_str[-2:]
            res_date = datetime.fromisoformat(iso_str)
            create_date = self.ticket.creation_time

            time_to_resolution = res_date - create_date
            logger.info("Time to resolution: %s", time_to_resolution)
            self.ticket.time_to_resolution = time_to_resolution.total_seconds()  
            self.resolution_date_updated = True

    @classmethod
    def save_dashboard_tickets(cls, dashboard_file):
        logger.info("Saving tickets to  %s", dashboard_file)
        tickets_dicts = []
        with open(dashboard_file, "w") as file:
            for ticket in cls.dashboard_tickets:
                ticket_dict = ticket.to_dict()
                tickets_dicts.append(ticket_dict)
            
            json.dump(tickets_dicts, file, indent=4)

    def update_dashboard_file(self):
        with open(self.dashboard_ticket_file, "r") as file:
            try:
                dashboard_file_dict = json.load(file) 
                if not dashboard_file_dict:
                    dashboard_file_dict = [] 
            except json.JSONDecodeError:
                dashboard_file_dict = []  

        with open(self.dashboard_ticket_file, "w") as file:
            ticket_dict = self.to_dict()
            dashboard_file_dict.append(ticket_dict)
            
            json.dump(dashboard_file_dict, file, indent=4)

    def save_new_ticket_data(self):
        with open("/Users/rballant/Documents/ticket_dashboard_data_new.json", "w") as file:
            json.dump(self.ticket_data, file, indent=4)

if __name__ == "__main__":
    server_name = socket.gethostname()
        
    key_handler = KeyHandler(logger, cert_path, key_path, ssh_key_path)
    key_handler.get_key_names()
    key_handler.get_personal_keys()

    ticket_handler = TicketHandler(dashboard_ticket_file, etp_processed_tickets_file, sps_processed_tickets_file)
    
    dashboard_ticket_data = ticket_handler.load_ticket_data(ticket_handler.dashboard_ticket_file)
    TicketHandler.dashboard_tickets = ticket_handler.create_tickets(dashboard_ticket_data)

    sps_processed_tickets_data = ticket_handler.load_ticket_data(ticket_handler.sps_processed_tickets_file)
    sps_processed_tickets = ticket_handler.create_tickets(sps_processed_tickets_data)
    
    etp_processed_tickets_data = ticket_handler.load_ticket_data(ticket_handler.etp_processed_tickets_file)
    etp_processed_tickets = ticket_handler.create_tickets(etp_processed_tickets_data)

    TicketHandler.processed_tickets = sps_processed_tickets + etp_processed_tickets
    
    dashboard_ticket_ids = {}
    dashboard_ticket_ids = {ticket.ticket_id: True for ticket in TicketHandler.dashboard_tickets}
    for ticket in TicketHandler.processed_tickets:
        exists = dashboard_ticket_ids.get(ticket.ticket_id, False)

        if exists is False:
            ticket_handler.ticket = ticket
            ticket_handler.check_required_data()
            if ticket_handler.get_time_to_resolution is True:
                ticket_handler.fetch_jira_ticket()
                ticket_handler.parse_jira_ticket_data()
                ticket_handler.update_resolution_time()
                if ticket_handler.resolution_date_updated is True:
                    TicketHandler.dashboard_tickets.append(ticket)

    TicketHandler.save_dashboard_tickets(ticket_handler.dashboard_ticket_file)
