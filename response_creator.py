import re

from config import logger


class ResponseCreator:
    def __init__(self, indicator) -> None:
        self.indicator = indicator

    def generate_source_response(self):
        logger.info(f"Generating source based response for {self.indicator.fqdn}")
        external_source_list = [
            "SOPHOS",
            "SURBL",
            "NETCRAFT",
            "EXTERNAL",
            "NOM-PROMOTION",
            "YOROI",
            "SUNBELT",
        ]

        malware_source_list = [
            "ETP:MANUAL_BLACKLIST_MALWARE",
            "NOMINUM_VC_MALWARE",
            "WEBROOT_MALWARE",
            "MANUAL_BLACKLIST_MALWARE",
            "SOPHOS_MAL_DOM_MALWARE",
            "SOPHOS_INFECTED_DOMAIN",
            "PARTIALLY_MALICIOUS_MALWARE",
            "SOPHOS_REPOSITORY",
            "VIRUS_TOTAL_MALWARE",
            "NOMINUM_IP_FRESH_MILK_TPS_MALWARE_IPS",
            "NOMINUM_IP_FRESH_MILK_TPS_UNIDENTIFIED_IPS"
        ]

        phishing_source_list = [
            "PHISHING",
            "ILLEGAL_PHISHING",
            "CRAWLED PHISHING",
            "ETP:MANUAL_BLACKLIST_PHISHING",
            "WEBROOT_PHISHING",
            "MANUAL_BLACKLIST_PHISHING",
            "NETCRAFT_PHISHING",
            "SURBL_PHISHING",
            "PHISHTANK",
            "PARTIALLY_MALICIOUS_PHISHING",
            "SOPHOS_PHISHING",
            "PMDURLSCAN"
        ]

        botnet_source_list = [
            "DGA_KNOWN_fAMILY",
            "CNC",
            "BMBNK_ALL_CNC",
            "BMBNK_DGA_ALL_CNC",
            "NOMINUM_VC_BOTNET",
            "JAPAN_ANTI_PHISHING",
            "NOMINUM_VC_PHISHING",
            "LOOKING_GLASS_CNC",
            "MANUAL_BLACKLIST_CNC",
            "CNFCKR_CNC",
            "NOMINUM_NPS",
            "SOPHOS_CALLHOME",
        ]

        malware_source_pattern = re.compile(
            r"|".join(re.escape(source) for source in malware_source_list),
            flags=re.IGNORECASE,
        )
        malware_source_matches = malware_source_pattern.findall(
            self.indicator.intel_source
        )
        
        external_source_pattern = re.compile(
            r"|".join(re.escape(source) for source in external_source_list),
            flags=re.IGNORECASE,
        )
        external_source_matches = external_source_pattern.findall(
            self.indicator.intel_source
        )
        
        phishing_source_pattern = re.compile(
            r"|".join(re.escape(source) for source in phishing_source_list),
            flags=re.IGNORECASE,
        )
        phishing_source_matches = phishing_source_pattern.findall(
            self.indicator.intel_source
        )
        
        botnet_source_pattern = re.compile(
            r"|".join(re.escape(source) for source in botnet_source_list),
            flags=re.IGNORECASE,
        )
        botnet_source_matches = botnet_source_pattern.findall(self.indicator.intel_source)

        self.indicator.vt_link = f"https://www.virustotal.com/gui/domain/{self.indicator.fqdn}/detection"

        if (
            "resolved IP and name pattern" in self.indicator.intel_source
            or "ncdippat" in self.indicator.intel_source
        ):
            if self.indicator.fqdn == self.indicator.matched_ioc:
                self.indicator.source_response = f"{self.indicator.fqdn} was flagged as it resolved to an IP address with a bad reputation. "
            else:
                if self.indicator.ip_in_intel is True:
                    self.indicator.source_response = f"{self.indicator.fqdn} was flagged as it resolves to {self.indicator.resolved_ip} which has indications of malicious activity. "
                else:
                    self.indicator.source_response = f"{self.indicator.fqdn} was flagged as it resolved to an IP address with a bad reputation. "
        elif malware_source_matches:
            if self.indicator.fqdn == self.indicator.matched_ioc:
                self.indicator.source_response = f"{self.indicator.fqdn} was flagged as malicious activity was identified. "
            else:
                self.indicator.source_response = f"{self.indicator.fqdn} was blocked as {self.indicator.matched_ioc} has been associated with malcious activity. "
        elif phishing_source_matches:
            if self.indicator.fqdn == self.indicator.matched_ioc:
                self.indicator.source_response = f"{self.indicator.fqdn} was flagged as it was identified for Phishing activity. "
            else:
                self.indicator.source_response = f"{self.indicator.fqdn} was blocked as {self.indicator.matched_ioc} was identified for Phishing activity. "
        elif external_source_matches:
            if self.indicator.fqdn == self.indicator.matched_ioc:
                self.indicator.source_response = f"{self.indicator.fqdn} was flagged as it was reported malicious by security vendors. "
            else:
                self.indicator.source_response = f"{self.indicator.fqdn} was blocked as {self.indicator.matched_ioc} was reported malicious by security vendors. "
        elif botnet_source_matches:
            if self.indicator.fqdn == self.indicator.matched_ioc:
                self.indicator.source_response = f"{self.indicator.fqdn} was flagged as it collided with a DGA. "
            else:
                self.indicator.source_response = f"{self.indicator.fqdn} was blocked as {self.indicator.matched_ioc} collided with a DGA. "
        else:
            self.indicator.source_response = ""

    def generate_comment_response(self):
        self.indicator.is_resolved = True
        if self.indicator.ip_in_intel is True:
            self.indicator.indicator_resolution = "In Progress"
        if self.indicator.indicator_resolution.lower() == "in progress":
            self.indicator.is_resolved = False
            self.indicator.ticket.requires_approval = True
            self.indicator.ticket.ticket_resolved = False
            self.indicator.comment = f" \n*{self.indicator.indicator_type}*: {self.indicator.fqdn} \n*Resolution*: {self.indicator.indicator_resolution} \n*COMMENTS*: \n{self.indicator.source_response} Analysis is currently in progress.\n "
        elif self.indicator.indicator_resolution.lower() == "allow":
            self.indicator.ticket.send_comment = True
            self.indicator.ticket.requires_approval = True
            self.indicator.comment = f" \n*{self.indicator.indicator_type}*: {self.indicator.fqdn} \n*RESOLUTION*: {self.indicator.indicator_resolution} \n*COMMENTS*: \n{self.indicator.source_response} {self.indicator.rule_response}\n "
        elif self.indicator.indicator_resolution.lower() == "block":
            self.indicator.ticket.send_comment = True
            self.indicator.ticket.requires_approval = True
            self.indicator.comment = f" \n*{self.indicator.indicator_type}*: {self.indicator.fqdn} \n*RESOLUTION*: {self.indicator.indicator_resolution} \n*COMMENTS*: \nFollowing a thorough investigation, several indications of {self.indicator.attribution} were found. \nTherefore the domain will be added to the intel. \n*Links*:\n{self.indicator.vt_link}\n"
        elif self.indicator.indicator_resolution.lower() == "closed":
            self.indicator.ticket.send_comment = True
            if self.indicator.ticket.ticket_type == "FP":
                if self.indicator.is_in_intel is True:
                    self.indicator.comment = f" \n*{self.indicator.indicator_type}*: {self.indicator.fqdn} \n*RESOLUTION*: {self.indicator.indicator_resolution} \n*COMMENTS*: \n{self.indicator.rule_response} \n*Links*:\n{self.indicator.vt_link}\n"
                else:
                    self.indicator.comment = f" \n*{self.indicator.indicator_type}*: {self.indicator.fqdn} \n*RESOLUTION*: {self.indicator.indicator_resolution} \n*COMMENTS*: \n{self.indicator.rule_response} \n"
            else:
                self.indicator.comment = f" \n*{self.indicator.indicator_type}*: {self.indicator.fqdn} \n*RESOLUTION*: {self.indicator.indicator_resolution} \n*COMMENTS*: \n{self.indicator.rule_response} \n*Links*:\n{self.indicator.vt_link}\n "
        else:
            print(f"Incorrect resolution: {self.indicator.indicator_resolution}")
            self.indicator.is_resolved = False
            self.indicator.ticket.ticket_resolved = False
            self.indicator.ticket.requires_approval = True
            self.indicator.ticket.send_comment = True


