import json
from datetime import datetime, timedelta
from typing import List

from indicator import Indicator


class Ticket:
    all_tickets = []
    ticket_ids = {}
    tickets_in_progress = {}
    previous_ticket_data = {}
    whitelist_domains = [
        "abuse.ch",
        "abuseipdb.com",
        "akamai.com",
        "akamai1.com",
        "alienvault.com",
        "any.run",
        "appurl.io",
        "bing.com",
        "bit.ly",
        "bitly.com",
        "bluecoat.com",
        "bp1.com",
        "brightcloud.com",
        "checkphish.ai",
        "facebook.com",
        "fortiguard.com",
        "google.com",
        "guardicore.com",
        "hybrid-analysis.com",
        "joesandbox.com",
        "linode.com",
        "name-list.match",
        "nomdebug.com",
        "o2.co.uk",
        "paloaltonetworks.com",
        "phishtank.org",
        "scamadviser.com",
        "shodan.io",
        "short.io",
        "shorturl.at",
        "slack.com",
        "sucuri.net",
        "swisscom.ch",
        "swisscom.com",
        "talium.co",
        "talosintelligence.com",
        "tinyurl.com",
        "trendmicro.com",
        "urldefense.com",
        "urlscan.io",
        "urlvoid.com",
        "virginmedia.com",
        "virustotal.com",
        "yahoo.com",
    ]

    def __init__(
        self, 
        logger,
        ticket_id: str,
        ticket_type: str,
        queue: str,
        reporter: str,
        is_guardicore_ticket: bool,
        fqdns: List[str],
        urls: List[str],
        ips: List[str],
        creation_time: str,
    ) -> None:
        self.logger = logger
        self.ticket_id: str = ticket_id
        self.ticket_type: str = ticket_type
        self.queue: str = queue
        self.reporter: str = reporter
        self.is_guardicore_ticket: bool = is_guardicore_ticket
        self.fqdns: List[str] = fqdns
        self.urls: List[str] = urls
        self.ips: List[str] = ips
        self.creation_time: str = creation_time
        self.indicators: List[Indicator] = []
        self.whitelist_additions: List[str] = []
        self.blacklist_additions: List[str] = []
        self.blacklist_removals: List[str] = []
        self.possible_changes: List[str] = []
        self.ticket_resolved: bool = True
        self.waiting_on_resolution: bool = False
        self.send_comment: bool = False
        self.block_comment: bool = False
        self.comment_failed: bool = False
        self.comment: str = ""
        self.changes_approved: bool = False
        self.requires_approval: bool = False
        self.override_resolved: bool = False
        self.time_to_response: str = ""
        self.time_to_resolution: str = ""
        self.linked_summary_ticket: str = ""
        if self.ticket_type.lower() != "summary":
            Ticket.all_tickets.append(self)
            Ticket.ticket_ids[self.ticket_id] = True

    def check_urls(self):
        urls = []
        for url in self.urls:
            benign_url = False
            for domain in Ticket.whitelist_domains:
                if domain in url:
                    benign_url = True
            
            if benign_url is False:
                urls.append(url)
        
        self.urls = urls

    def set_process_flag(self):
        if self.urls:
            self.block_comment = True
        if self.ips:
            self.block_comment = True

    def append_indicator(self, indicator):
        self.indicators.append(indicator)

    def set_comment_greeting(self):
        self.comment_greeting = f"Hi {self.reporter}\n\n"

    def set_comment_sign_off(self):
        self.comment_sign_off = "\n\nIf there are any further questions we will be happy to respond.\nSecOps Team"

    def set_ticket_comment(self):
        if self.ticket_responses:
            self.comment = self.comment_greeting + self.ticket_responses + self.comment_sign_off
        else:
            self.comment = ""
            self.send_comment = False

    def to_dict(self):
        indicators_dict = [indicator.to_dict() for indicator in self.indicators]

        ticket_dict = self.__dict__.copy()
        if isinstance(self.creation_time, datetime):
            ticket_dict["creation_time"] = self.creation_time.isoformat()  
        if isinstance(self.time_to_response, timedelta):
            ticket_dict["time_to_response"] = self.time_to_response.total_seconds()  
        if isinstance(self.time_to_resolution, timedelta):
            ticket_dict["time_to_resolution"] = self.time_to_resolution.total_seconds()  

        ticket_dict.pop("indicators", None)  
        ticket_dict.pop("logger", None)  

        ticket_dict["indicators"] = indicators_dict 

        return ticket_dict

    @classmethod
    def from_dict(cls, data, logger):
        skip_keys = [
            "ticket_id",
            "ticket_type",
            "queue",
            "reporter",
            "is_guardicore_ticket",
            "fqdns",
            "urls",
            "ips",
            "creation_time",
            "indicators",
        ] 
        data["creation_time"] = datetime.fromisoformat(data["creation_time"])
        if "time_to_response" in data and isinstance(data["time_to_response"], (int, float)):
            data["time_to_response"] = timedelta(seconds=data["time_to_response"])
        else:
            data["time_to_response"] = None  
        
        if "time_to_resolution" in data and isinstance(data["time_to_resolution"], (int, float)):
            data["time_to_resolution"] = timedelta(seconds=data["time_to_resolution"])
        else:
            data["time_to_resolution"] = None  
        

        ticket = cls(
            logger,
            ticket_id=data["ticket_id"],
            ticket_type=data["ticket_type"],
            queue=data["queue"],
            reporter=data["reporter"],
            is_guardicore_ticket=data["is_guardicore_ticket"],
            fqdns=data["fqdns"],
            urls=data["urls"],
            ips=data["ips"],
            creation_time=data["creation_time"],
        )

        ticket.indicators = []
        for indicator_data in data.get("indicators", []):
            indicator = Indicator.from_dict(indicator_data, ticket, logger) 
            indicator.add_indicator_to_ticket()

        for key, value in data.items():
            if key not in skip_keys:
                setattr(ticket, key, value)
        return ticket

    @classmethod
    def link_summary_ticket(cls, summary_id):
        for ticket in cls.all_tickets:
            if not ticket.linked_summary_ticket:
                ticket.linked_summary_ticket = summary_id

    @classmethod
    def save_current_tickets(cls, in_progress_file):
        tickets_dicts = []
        with open(in_progress_file, "w") as file:
            for ticket in cls.all_tickets:
                ticket_dict = ticket.to_dict()
                tickets_dicts.append(ticket_dict)
            
            json.dump(tickets_dicts, file, indent=4)

    def update_tickets_in_progress(self, in_progress_file):
        with open(in_progress_file, "r") as file:
            try:
                in_progress_dict = json.load(file) 
                if not in_progress_dict:
                    in_progress_dict = [] 
            except json.JSONDecodeError:
                in_progress_dict = []  

        with open(in_progress_file, "w") as file:
            ticket_dict = self.to_dict()
            in_progress_dict.append(ticket_dict)
            
            json.dump(in_progress_dict, file, indent=4)

    @classmethod
    def load_ticket_data(cls, tickets_in_progress_file):
        with open(tickets_in_progress_file, "r") as file:
            if file:
                Ticket.previous_ticket_data = json.load(file)

    @classmethod
    def create_tickets(cls, logger):
        for ticket in Ticket.previous_ticket_data:
            Ticket.from_dict(ticket, logger)

    @classmethod
    def get_tickets_in_progress(cls):
        for ticket in Ticket.previous_ticket_data:
            Ticket.tickets_in_progress[ticket.get("ticket_id")] = True