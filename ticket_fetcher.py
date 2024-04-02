import json
import os
import re

import requests

import get_az_secret
from config import (cert_name, cert_path, jira_search_api, key_name, key_path,
                    logger)


class TicketFetcher:
    def __init__(self, queue="sps") -> None:
        self.queue = queue
        self.get_keys()
        self.get_tickets()
        self.parse_tickets()

    def get_keys(self):
        self.cert_path = 'osemyono.crt'
        # with open(self.cert_path, "r") as f:
        #     cert = f.readlines()

        # with open(self.cert_path, 'w') as f:
        #     f.write(cert[0].replace('\\n','\n').replace('\n ','\n'))

        # cert = get_az_secret.get_az_secret('osemyono-crt')
        # key = get_az_secret.get_az_secret('osemyono-key')
        self.key_path = 'osemyono.key'
        # with open(self.key_path, "r") as f:
        #     key = f.readlines()
        # with open(self.key_path, 'w') as f:
        #     f.write(key[0].replace('\\n','\n').replace('\n ','\n'))

    def get_tickets(self):
        logger.info("Fetching tickets from {} queue", self.queue.lower())

        if self.queue.lower() == "sps":
            jql_query = f'project="ReCat Sec Ops Requests" AND status in ("Open", "In Progress", "Reopened") AND assignee IS EMPTY'

        if self.queue.lower() == "etp":
            jql_query = 'project="Enterprise Tier 3 Escalation Support" and "Next Steps" ~ SecOps'

        params = {"jql": jql_query, "maxResults": 100}

        self.req = requests.get(
            jira_search_api,
            params=params,
            cert=(self.cert_path, self.key_path),
            verify=False,
        )

    def parse_tickets(self):
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
                        if description:
                            domains, urls = collect_entities(description, ticket_id)
                        summary = fields.get("summary")
                        if summary:
                            ticket_type = get_ticket_type(summary)
                        self.tickets[ticket_id] = {
                            "ticket_type": ticket_type,
                            "summary": fields.get("summary"),
                            "first_name": first_name,
                            "reporter": reporter,
                            "description": description,
                            "domains": list(domains),
                            "urls": list(urls),
                            "entity_type": "DOMAIN",
                            "components": fields.get("components"),
                            "labels": entry.get("labels"),
                        }
        else:
            logger.info(f"Tickets Not Retrieved - Error: {self.req.status_code}")

        # os.remove(cert_path)
        # os.remove(key_path)


def collect_urls(description):
    pattern = re.compile(
        "([a-zA-Z]+://)?([\w-]+(\[\.\]|\.))+[\w]{2,}/.*"
    )
    matches = re.finditer(pattern, description)
    urls = [match.group(0) for match in matches]
    urls = sorted(urls, key=len, reverse=True)
    for url in urls:
        description = description.replace(url, " ")
    return description, urls


def collect_domains(decsription):
    pattern = re.compile(
        "((?=[a-z0-9-]{1,63}\.)(xn--)?[a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,63}"
    )
    matches = re.finditer(pattern, decsription)
    domains = [(match.group(0)) for match in matches]
    return domains


def collect_entities(desc, ticket):
    logger.info("Extracting entities from tickets")
    desc = clean_description(desc)
    desc, urls = collect_urls(desc)
    domains = collect_domains(desc)
    logger.info(f"Extracted {len(set(domains))} domains and {len(set(urls))} from {ticket}")
    return set(domains), set(urls)


def clean_description(description):
    logger.info("Cleaning description")
    characters_to_remove = ["[", "]", "*", '"', "'", "{", "}", ";", "\\", "(", ")", ","]
    desc = "".join(
        char for char in description if char not in characters_to_remove
    ).strip()
    if "Carrier Support team" in desc:
        desc = desc.split("Carrier Support team")[0]
    logger.info("Description cleaned")
    return desc


def get_ticket_type(summary):
    if "fn" in summary.lower() or "false negative" in summary.lower():
        return "FN"
    elif "fp" in summary.lower() or "false positive" in summary.lower():
        return "FP"
    else:
        return "None"
