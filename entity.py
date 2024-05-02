import tldextract as tld
from config import logger
import re


class Entity:
    entity_list = []

    def __init__(self, queue, domain, entity_type, urls, ticket, ticket_type, reporter) -> None:
        self.queue = queue
        self.entity = domain
        self.urls = urls
        self.entity_type = entity_type
        self.ticket_id = ticket
        self.ticket_type = ticket_type
        self.reporter = reporter
        self.clean_domain()
        self.get_core_domain()
        self.append_entity()

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
        ]
        if self.core_domain not in whitelist_domains:
            if self.is_not_file_extension():
                Entity.entity_list.append(self)
                print(f"Entity Found: {self.entity}")
                logger.info(f"{self.entity} entity instance created")
            else:
                print(f"Skipping {self.entity} - file detected")
                logger.info(f"Skipping {self.entity} - file detected")

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
