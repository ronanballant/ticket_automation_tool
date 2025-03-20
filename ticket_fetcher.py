import json
import re
from datetime import datetime
import requests
import tldextract as tld

from config import jira_search_api, logger

class TicketFetcher:
    def __init__(self, cert_path, key_path, queue="sps") -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self.queue = queue

    def get_tickets(self):
        try:
            if self.queue.lower() == "sps":
                jql_query = f'project="ReCat Sec Ops Requests" AND status = "Open" AND assignee IS EMPTY'
                # jql_query = f'project="ReCat Sec Ops Requests" AND status IS "Open" AND assignee IS EMPTY'
                # jql_query = f'project="ReCat Sec Ops Requests" AND issue = "RCSOR-7408"'

            if self.queue.lower() == "etp":
                jql_query = 'project="Enterprise Tier 3 Escalation Support" AND assignee is EMPTY AND status in (New, Open) and "Next Steps" ~ SecOps'
                # jql_query = 'project="Enterprise Tier 3 Escalation Support" AND issue = "ENTESC-14166"'
                # jql_query = 'project="ETPESC" AND issue = "ETPESC-9841"'
            params = {"jql": jql_query, "maxResults": 100}

            self.req = requests.get(
                jira_search_api,
                params=params,
                cert=(self.cert_path, self.key_path),
                verify=False,
            )
        except Exception as e:
            print(f"JIRA ticket API Failed: {e}")
            logger.error(f"JIRA ticket API Failed: {e}")
            raise

    def parse_tickets(self):
        try:
            if self.req.status_code == 200:
                logger.info("Tickets Retrieved")
                logger.info("Parsing tickets")
                result_dict = json.loads(self.req.text)
                issues = result_dict.get("issues")
                self.tickets = {}
                if issues:
                    for entry in issues:
                        ticket_id = entry.get("key")
                        fields = entry.get("fields")
                        if fields:
                            creation_time = datetime.strptime(fields.get("created"), '%Y-%m-%dT%H:%M:%S.%f%z')
                            reporter_data = fields.get("reporter")
                            full_name = reporter_data.get("displayName")
                            user_name = reporter_data.get("name")
                            if full_name == "svcCarrierSupport":
                                first_name = "support team"
                                reporter = "support team"
                            else:
                                first_name = full_name.split(" ")[0]
                                reporter = "[~{}]".format(user_name)
                            description = fields.get("description")
                            summary = fields.get("summary")
                            customer = fields.get("customfield_12703", "")
                            if description:
                                fqdns, urls, ips = collect_indicators(
                                    summary, description, ticket_id
                                )
                                is_guardicor_ticket = is_guardicore(
                                    customer, description
                                )
                            if summary:
                                components = fields.get("components")
                                if components:
                                    component = ",".join([component.get("name") for component in components])
                                    component = component.replace("_", " ")
                                else:
                                    component = ""

                                if "secops false negative" in component.lower():
                                    ticket_type = "FN"
                                elif "secops false positive" in component.lower():
                                    ticket_type = "FP"
                                else:
                                    ticket_type = get_ticket_type(summary, description)

                            self.tickets[ticket_id] = {
                                "ticket_type": ticket_type,
                                "summary": fields.get("summary"),
                                "first_name": first_name,
                                "reporter": reporter,
                                "description": description,
                                "fqdns": list(fqdns),
                                "urls": list(urls),
                                "ips": list(ips),
                                "indicator_type": "DOMAIN",
                                "components": fields.get("components"),
                                "labels": fields.get("labels"),
                                "is_guardicore_ticket": is_guardicor_ticket,
                                "creation_time": creation_time,
                            }
            else:
                print(
                    f"Error Fetching Tickets - Bad Status code: {self.req.status_code}"
                )
                logger.info(
                    f"Error Fetching Tickets - Bad Status code: {self.req.status_code}"
                )
        except Exception as e:
            print(f"Failed to parse ticket response: {e}")
            logger.error(f"Failed to parse ticket response: {e}")
            raise

def is_guardicore(customer, description):
    if customer:
        text = customer + description
    else:
        text = description
    return True if "guardicore" in text.lower() else False

def clean_description(description):
    logger.info("Cleaning description")
    pattern = r"{color[^}]*}|{code[^}]*}|{noformat[^}]*}"
    description = re.sub(pattern, " ", description)
    pattern = r"\[([^\|]*)\|.*?\]"  
    description = re.sub(pattern, r"\1", description)
    description = (
        description
        .replace("{quote}", " ")
        .replace("|", " ")
        .replace("[:]", ":")
        .replace("[.]", ".")
        .replace("[", "")
        .replace("]", "")
        .replace("*", " ")
        .replace("'", " ")
        .replace('"', " ")
        .replace("{.}", ".")
        .replace("{:}", ":")
        .replace(";", " ")
        .replace(",", " ")
        .replace("\\", "")
        .replace("(", " ")
        .replace(")", " ")
    ).strip()

    if "carrier support team" in description:
        description = description.split("carrier support team")[0]

    logger.info("Description cleaned")
    return description

def collect_urls(description):
    words = description.split()
    # pattern = re.compile("([a-zA-Z]+://)?([\w-]+(\[\.\]|\.))+[\w]{2,}/.*")
    pattern = re.compile("([a-zA-Z]+://)?([\\w-]+(\\[\\.\\]|\\.)+)+[\\w]{2,}(:\\d+)?/.*")

    matched_urls = []
    for word in words:
        matches = re.finditer(pattern, word)
        urls = [match.group(0) for match in matches]
        matched_urls += urls

    urls = sorted(matched_urls, key=len, reverse=True)
    for url in urls:
        description = description.replace(url, " ")
    return description, list(set(urls))

def collect_fqdns(description):
    words = description.split()
    pattern = re.compile(
        "((?=[a-z0-9-]{1,63}\\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,63}"
    )
    
    matched_fqdns = []
    for word in words:
        if "@" not in word:
            matches = re.finditer(pattern, word)
            fqdn_matches = [(match.group(0)) for match in matches]
            matched_fqdns += fqdn_matches

    matches = [
        fqdn[4:] if fqdn.startswith("www.") else fqdn
        for fqdn in matched_fqdns
    ]

    fqdns = []
    for fqdn in matches:
        if tld.extract(fqdn).suffix:
            fqdns.append(fqdn)
        else:
            logger.info(f"Invalid Suffix for {fqdn}")

    return list(set(fqdns))

def collect_ips(description):
    ipv4_pattern = r"\b(?:\d{1,3}(\[.\]|\.)\d{1,3}(\[.\]|\.)\d{1,3}(\[.\]|\.)\d{1,3})(?:/\d{1,2})?\b"

    words = description.split()
    matched_ips = []
    for word in words:
        matches = re.finditer(ipv4_pattern, word)
        ip_matches = [(match.group(0)) for match in matches]
        matched_ips += ip_matches

    return list(set(matched_ips))

def collect_indicators(summary, desc, ticket):
    summary = summary.lower()
    desc = desc.lower()
    text = summary + " " + desc
    logger.info("Extracting entities from tickets")
    desc = clean_description(text)
    desc, urls = collect_urls(desc)
    fqdns = collect_fqdns(desc)
    ips = collect_ips(desc)
    logger.info(
        f"Extracted {len(set(fqdns))} FQDNs, {len(set(ips))} IPs and {len(set(urls))} URLs from {ticket}"
    )
    return fqdns, urls, ips


def get_ticket_type(summary, description):
    summary = summary.lower()
    description = description.lower()
    
    if "exfil" in description or "exfiltration" in description:
        return "None"
    
    if "fn:" in summary or "false negative" in summary:
        return "FN"
    elif "fp:" in summary or "false positive" in summary:
        return "FP"
    elif "fn - " in summary or "false positive" in summary:
        return "FN"
    elif "fp - " in summary or "false positive" in summary:
        return "FP"
    elif "fn | " in summary or "false positive" in summary:
        return "FN"
    elif "fp | " in summary or "false positive" in summary:
        return "FP"
    elif " fn " in description or "false negative" in description:
        return "FP"
    elif " fp " in description or "false positive" in description:
        return "FP"
    else:
        return "None"
