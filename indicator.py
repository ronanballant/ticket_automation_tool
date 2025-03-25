import re
from datetime import timedelta
from typing import List

import tldextract as tld
from intel_entry import IntelEntry
import dns.resolver


class Indicator:
    def __init__(
        self,
        logger,
        fqdn: str,
        ticket,
        indicator_type: str,
    ) -> None:
        self.logger = logger
        self.fqdn: str = fqdn
        self.indicator_type: str = indicator_type
        self.ticket = ticket
        self.domain: str = ""
        self.indicator_type: str = "DOMAIN"
        self.intel_feed: str = "-"
        self.intel_confidence: str = "-"
        self.intel_source: str = "-"
        self.confidence_level: str = "-"
        self.subdomain_count: int = 0
        self.url_count: int = 0
        self.is_in_intel: bool = False
        self.e_list_entry: bool = False
        self.subdomain_only: bool = False
        self.is_internal: bool = False
        self.vt_query_url: str = ""
        self.vt_link: str = ""
        self.has_vt_data: bool = False
        self.vt_indications: str = "-"
        self.rescan_id = None
        self.creation_date: str = "-"
        self.last_scanned: str = "-"
        self.categories: str = "-"
        self.response_code: str = "-"
        self.analysis_results: str = "-"
        self.tags: str = "-"
        self.data_source: str = "-"
        self.days_since_creation: str = "-"
        self.days_since_last_scanned: str = "-"
        self.is_filtered: str = "-"
        self.intel_category_strength: str = "-"
        self.indicator_resolution: str = ""
        self.rule_response: str = ""
        self.source_response: str = ""
        self.is_resolved: bool = False
        self.comment: str = ""
        self.attribution: str = ""                
        self.attribution_id = "-"
        self.attribution_description = "-"
        self.whitelisted_domain = True
        self.file_extension = False
        self.legitimate_indicator = False
        self.intel_entries: List[IntelEntry] = []
        self.candidates = []
        self.resolved_ip: str = None
        self.ip_in_intel: bool = False
        self.matched_ioc: str = "-"

    def clean_fqdn(self):
        self.logger.info(f"Cleaning {self.fqdn}")
        characters_to_remove = [
            "[",
            "]",
            "*",
            '"',
            "'",
            "{",
            "}",
            ":",
            ";",
            "\\",
            "/",
            "(",
            ")",
            ",",
        ]
        self.fqdn = "".join(
            char for char in self.fqdn if char not in characters_to_remove
        ).strip()

    def get_domain(self):
        self.domain = tld.extract(self.fqdn).registered_domain

    def is_whitelisted_domains(self):
        if self.domain:
            if self.domain not in self.ticket.whitelist_domains:
                self.whitelisted_domain = False
        else:
            self.logger.info(f"Skipping {self.fqdn} - Could not identify parent domain")

    def is_file_extension(self):
        file_extension_pattern = r"\.(txt|exc|tsv|csv|py|json|ext)$"
        match = re.search(file_extension_pattern, self.fqdn, re.IGNORECASE)
        self.file_extension = True if match else False

    def is_legitimate_indicator(self):
        self.legitimate_indicator = False
        if self.whitelisted_domain is False:
            if self.file_extension is False:
                self.legitimate_indicator = True
                self.logger.info(f"{self.fqdn} indicator instance created")
            else:
                self.logger.info(f"Skipping {self.fqdn} - File extension detected")
        else:
            self.logger.info(f"Skipping {self.fqdn} - Whitelisted domain")

    def add_indicator_to_ticket(self):
        if self.legitimate_indicator is True:
            self.ticket.append_indicator(self)

    def append_intel_entry(self, intel_entry):
        self.intel_entries.append(intel_entry)

    def to_dict(self):
        intel_entries_dict = [entry.to_dict() for entry in self.intel_entries]

        indicator_dict = self.__dict__.copy()
        indicator_dict["time_to_response"] = self.time_to_response.total_seconds()  

        indicator_dict.pop("ticket", None)  
        indicator_dict.pop("mongo_results", None)  
        indicator_dict.pop("analysis_results", None)  

        indicator_dict["intel_entries"] = intel_entries_dict 

        return indicator_dict

    @classmethod
    def from_dict(cls, data, ticket, logger):

        indicator = cls(
            logger,
            fqdn=data["fqdn"],
            indicator_type=data["indicator_type"],
            ticket=ticket,  
        )
        
        indicator.intel_entries = []
        for intel_entry_data in data.get("intel_entries", []):
            intel_entry = IntelEntry.from_dict(intel_entry_data, indicator, logger) 
            intel_entry.append_to_indicator()

        for key, value in data.items():
            if key != "fqdn" and key != "indicator_type" and key != "intel_entries":
                setattr(indicator, key, value)

        indicator.time_to_response = timedelta(0.00, indicator.time_to_response)
        return indicator

    def get_candidates(self):
        if self.legitimate_indicator is True:
            subdomains = []
            fqdn = self.fqdn
            if self.fqdn == self.domain:
                self.candidates = [self.domain]
            else:
                fqdn = fqdn.replace(f".{self.domain}", "")
                parts = fqdn.split(".")
                subdomains = [
                    ".".join(parts[i:]) + f".{self.domain}" for i in range(len(parts))
                ]
                subdomains.append(self.domain)
                self.candidates = subdomains

    def get_etp_fqdn(self):
        if self.fqdn[-1] == ".":
            self.etp_fqdn = self.fqdn
            self.fqdn = self.fqdn[:-1]
        else:
            self.etp_fqdn = self.fqdn + "."

    def get_resolved_ip(self):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        try:
            answer = resolver.resolve(self.fqdn, "A")
            self.resolved_ips = [ip.address for ip in answer]
        except dns.resolver.NXDOMAIN:
            self.resolved_ips = []
            return "Domain does not exist"
        except dns.resolver.NoAnswer:
            self.resolved_ips = []
            return "No answer from DNS"
        except dns.resolver.Timeout:
            self.resolved_ips = []
            return "DNS query timed out"