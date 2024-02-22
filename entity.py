from config import logger


class Entity:
    entity_list = []

    def __init__(
        self, queue, domain, entity_type, ticket, ticket_type, reporter
    ) -> None:
        self.queue = queue
        self.entity = domain
        self.entity_type = entity_type
        self.ticket_id = ticket
        self.ticket_type = ticket_type
        self.reporter = reporter
        self.clean_domain()
        self.append_entity()

    def append_entity(self):
        whitelist_domains = [
            "virginmedia.com",
            "www.virginmedia.com",
            "urldefense.com",
            "www.o2.co.uk",
            "o2.co.uk",
        ]
        if self.entity not in whitelist_domains:
            Entity.entity_list.append(self)
            logger.info("{} entity instance created", self.entity)

    def clean_domain(self):
        logger.info("Cleaning domain name")
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
