import tldextract as tld
from config import logger
from typing import List
import re


class Entity:
    def __init__(self, queue: str, domain: str, entity_type: str, urls: List[str], ticket: str, ticket_type: str, reporter: str, is_guardicore_ticket: bool, ips: List[str]) -> None:
        self.queue: str = queue
        self.entity: str = domain
        self.urls: List[str] = urls
        self.entity_type: str = entity_type
        self.ticket_id: str = ticket
        self.ticket_type: str = ticket_type
        self.reporter: str = reporter
        self.is_guardicore_ticket: bool = is_guardicore_ticket
        self.ips: List[str] = ips
        self.intel_feed: str = '-'
        self.intel_confidence: str = '-'
        self.intel_source: str = "-"
        self.confidence_level: str = "-"
        self.subdomain_count: int = 0
        self.url_count: int = 0 
        self.is_in_intel: bool = False
        self.e_list_entry: bool = False
        self.subdomain_only: bool = False
        self.is_internal: bool = False
        self.domain: str = ''
        self.vt_url: str = ''
        self.vt_link: str = ''
        self.has_data: bool = False
        self.positives: str = "-"
        self.creation_date: str = "-"
        self.last_seen: str = "-"
        self.categories: str = "-"
        self.response_code: str = "-"
        self.analysis_results: str = "-"
        self.tags: str = "-"
        self.data_source: str = "-"
        self.days_since_creation: str = "-"
        self.days_since_last_seen: str = "-"
        self.is_filtered: str = "-"
        self.intel_category_strength: str = "-"
        self.resolution: str = ''
        self.response: str = ''
        self.source_response: str = ''
        self.is_resolved: bool = False
        self.comment: str = ''
        try:
            self.clean_domain()
            self.get_core_domain()
            self.append_entity()
        except Exception as e:
            print(f"Failed to create entity instance: {e}")
            logger.error(f"Failed to create entity instance: {e}")
            raise


    def append_entity(self):
        whitelist_domains = [
            "abuse.ch",
            "akamai.com",
            "alienvault.com",
            "any.run",
            "bing.com",
            "bluecoat.com",
            "brightcloud.com",
            "fortiguard.com",
            "google.com",
            "hybrid-analysis.com",
            "joesandbox.com",
            "nomdebug.com",
            "o2.co.uk",
            "paloaltonetworks.com",
            "checkphish.ai",
            "phishtank.org",
            "scamadviser.com",
            "slack.com",
            "sucuri.net",
            "talium.co",
            "talosintelligence.com",
            "trendmicro.com",
            "urldefense.com",
            "urlscan.io",
            "urlvoid.com",
            "virginmedia.com",
            "virustotal.com",
            "yahoo.com",
            "akamai1.com",
            "bp1.com",
            "facebook.com",
            "name-list.match",
        ]
        
        self.append_entity = False
        if self.core_domain:
            if self.core_domain not in whitelist_domains:
                if self.is_not_file_extension():
                    self.append_entity = True
                    print(f"Entity Found: {self.entity}")
                    logger.info(f"{self.entity} entity instance created")
                else:
                    print(f"Skipping {self.entity} - file detected")
                    logger.info(f"Skipping {self.entity} - file detected")
            else:
                print(f"Whitelisted domain Skipped - {self.entity}")
                logger.info(f"Whitelisted domain Skipped - {self.entity}")
        else:
            print(f"Entity Skipped - {self.entity}")
            logger.info(f"Entity Skipped - {self.entity}")


    def clean_domain(self):
        logger.info(f"Cleaning {self.entity}")
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
        self.domain = "".join(
            char for char in self.entity if char not in characters_to_remove
        ).strip()

    def is_not_file_extension(self):
        file_extension_pattern = r'\.(txt|.exc|tsv|csv|py|json|ext)$'
        return not re.match(file_extension_pattern, self.core_domain)

    def get_core_domain(self):
        self.core_domain = tld.extract(self.entity).registered_domain
