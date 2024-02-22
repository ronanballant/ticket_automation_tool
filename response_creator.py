import re

from config import logger


class ResponseCreator:
    def __init__(self, entity) -> None:
        self.entity = entity
        self.get_feed_response()
        self.create_response()

    def get_feed_response(self):
        logger.info("Generating source based response for {}", self.entity.entity)
        external_source_list = [
            "sophos",
            "surbl",
            "netcraft",
            "External",
            "nom-promotion",
            "yoroi",
            "sunbelt",
        ]

        phishing_source_list = [
            "Phishing" "illegal_phishing",
            "Crawled phishing",
            "ETP:MANUAL_BLACKLIST_PHISHING",
        ]

        botnet_source_list = ["DGA_Known_family"]

        external_source_pattern = re.compile(
            r"|".join(re.escape(source) for source in external_source_list),
            flags=re.IGNORECASE,
        )
        external_source_matches = external_source_pattern.findall(
            self.entity.intel_source
        )
        phishing_source_pattern = re.compile(
            r"|".join(re.escape(source) for source in phishing_source_list),
            flags=re.IGNORECASE,
        )
        phishing_source_matches = phishing_source_pattern.findall(
            self.entity.intel_source
        )
        botnet_source_pattern = re.compile(
            r"|".join(re.escape(source) for source in botnet_source_list),
            flags=re.IGNORECASE,
        )
        botnet_source_matches = botnet_source_pattern.findall(self.entity.intel_source)

        self.entity.vt_link = (
            "https://www.virustotal.com/gui/domain/{}/detection".format(
                self.entity.domain
            )
        )

        if (
            "resolved IP and name pattern" in self.entity.intel_source
            or "ncdippat" in self.entity.intel_source
        ):
            self.entity.source_response = "{} was flagged as it resolved to an IP address with a bad reputation. However no current threat has been identified. ".format(
                self.entity.entity
            )
        elif phishing_source_matches:
            self.entity.source_response = "{} was flagged as it was identified for Phishing activity. However no current Phishing threat has been identified. ".format(
                self.entity.entity
            )
        elif external_source_matches:
            self.entity.source_response = "{} was flagged as it was reported malicious by security vendors. However these indications have been removed and the domain appears clean. ".format(
                self.entity.entity
            )
        elif botnet_source_matches:
            self.entity.source_response = "{} was flagged as it collided with a DGA. However the domain appears legitimate and no current threat has been identified. ".format(
                self.entity.entity
            )
        elif "ETP:MANUAL_BLACKLIST_MALWARE" in self.entity.intel_source:
            self.entity.source_response = "{} was flagged for malware distribution. However no current threat has been identified. ".format(
                self.entity.entity
            )
        else:
            self.entity.source_response = ""

    def create_response(self):
        self.entity.comment = self.entity.response + self.entity.source_response
