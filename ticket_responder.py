import csv
import json
import os
import time

import requests
import traceback
import get_az_secret
from config import (cert_name, cert_path, jira_ticket_api,
                    key_name, key_path, logger, response_file_path,
                    unresolved_file_path)


class TicketResponder:
    def __init__(self, entities):
        self.entities = entities
        self.time = time.time()
        self.unresolved_file_path = unresolved_file_path + f"{self.time}_domains_to_analyse.csv"
        self.response_file_path = response_file_path + f"{self.time}_result_comments.csv"
        self.get_keys()
        self.group_tickets()

    def get_keys(self):
        self.cert_path = "osemyono.crt"
        self.key_path = "osemyono.key"

    # def get_keys(self):
    #     cert = get_az_secret.get_az_secret(cert_name)
    #     self.cert_path = cert_path
    #     with open(self.cert_path, "w") as f:
    #         f.write(cert.replace("\\n", "\n").replace("\n ", "\n"))
    #     key = get_az_secret.get_az_secret(key_name)
    #     self.key_path = key_path
    #     with open(self.key_path, "w") as f:
    #         f.write(key.replace("\\n", "\n").replace("\n ", "\n"))

    def group_tickets(self):
        logger.info("Grouping by ticket")
        tickets = {}
        open_tickets = []
        for entity in self.entities:
            self.queue = entity.queue
            if entity.ticket_id not in tickets.keys():
                tickets[entity.ticket_id] = {
                    "responses": [],
                    "reporter": entity.reporter,
                    "is_resolved": [],
                }
            else:
                pass
            
            tickets[entity.ticket_id]["responses"].append((entity.comment))
            tickets[entity.ticket_id]["is_resolved"].append(entity.is_resolved)
            open_tickets.append((entity.domain, entity.ticket_id, entity.comment))

        self.responses = tickets
        self.unresolved_entities = open_tickets

    def update_tickets(self):
        self.resolved_tickets = []
        for ticket, values in self.responses.items():
            reporter = values.get("reporter")
            greeting = "Hi {}\n\n".format(reporter)
            end = "\n\nIf there are any further questions we will be happy to respond.\nSecOPs Team"
            comment = greeting + "\n\n".join(values.get("responses")) + end
            send_comment = False
            resolved = True
            for response in values.get("responses"):
                if "is currently under investigation" in response:
                    resolved = False
                else:
                    send_comment = True

            # Un-comment after test week
            # if send_comment is True:
            #     self.add_comment(self.queue, ticket, comment)

            entity_resolutions = values.get("is_resolved")
            ticket_resolved = True
            for resolution in entity_resolutions:
                if resolution is False:
                    ticket_resolved = False
            
            if ticket_resolved is True:
                self.resolved_tickets.append(ticket)

            # Un-comment after test week
            # self.close_ticket(ticket, resolved)

        # os.remove(cert_path)
        # os.remove(key_path)

    def add_comment(self, queue, ticket, comment, label="", assignee="rballant"):
        logger.info(f"Adding comment to {ticket}")
        url = jira_ticket_api + ticket

        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        if queue.lower() == "sps":
            payload = {
                "update": {
                    "comment": [{"add": {"body": comment}}],
                    "assignee": [{"set": {"name": assignee}}],
                }
            }
        else:
            payload = {
                "update": {
                    "comment": [{"add": {"body": comment}}],
                    "assignee": [{"set": {"name": assignee}}],
                    "labels": [{"add": label}],
                }
            }

        response = requests.request(
            "PUT", url, json=payload, headers=headers, cert=(self.cert_path, self.key_path), verify=False
        )

    def create_sps_ticket(self):
        allow_list_entries = []
        block_list_entries = []
        closed_list = [
            "||status||ticket_id||ticket_type||entity||subdomains||malicious reports||last_seen||categories||feed||source||confidence||resolution||response||"
        ]
        open_list = [
            "||status||ticket_id||ticket_type||entity||subdomains||malicious reports||last_seen||categories||feed||source||confidence||resolution||response||"
        ]
        sorted_entities = sorted(
            self.entities, key=lambda x: x.ticket_id, reverse=False
        )
        for entity in sorted_entities:
            if entity.resolution.lower() == "in progress":
                line = f"|In Progress|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.subdomain_count}|{entity.positives}|{entity.last_seen}|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.intel_confidence}|{entity.resolution}|{entity.source_response} {entity.response}|"
                open_list.append(line)
            else:
                line = f"|Closed|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.subdomain_count}|{entity.positives}|{entity.last_seen}|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.intel_confidence}|{entity.resolution}|{entity.source_response} {entity.response}|"
                closed_list.append(line)

            if entity.resolution.lower() == "allow":
                allow_list_entries.append(f"{entity.entity},{entity.ticket_id}")
            if entity.resolution.lower() == "block":
                block_list_entries.append(
                    f"{entity.entity},{entity.ticket_id},{entity.attribute}"
                )

        open_table = "\n".join(open_list)
        closed_table = "\n".join(closed_list)
        allow_strings = "\n".join(allow_list_entries)
        block_strings = "\n".join(block_list_entries)
        description = (
            " \n+{color:#de350b}*Please see the comment section to view open and closed cases.*{color}+\n\n\n"
            + "*Allow List*\n{code:java}\n"
            + allow_strings
            + "{code}"
            + "\n\n*Block List*\n{code:java}\n"
            + block_strings
            + "{code}"
        )

        headers = {"Content-Type": "application/json"}

        data = {
            "fields": {
                "project": {"key": "RCSOR"},
                "summary": "Automation Results",
                "description": description,
                "issuetype": {"name": "Task"},
            }
        }

        response = requests.post(
            jira_ticket_api,
            json=data,
            headers=headers,
            cert=(self.cert_path, self.key_path),
            verify=False,
        )

        issue_decoded = response.content.decode("utf-8")
        issue_json = json.loads(issue_decoded)
        issue = issue_json.get("key")

        comment = (
            "*Open Cases*\n" + open_table + "\n\n\n*Closed Cases*\n" + closed_table
        )

        self.add_comment("SPS", issue, comment)

    def create_etp_ticket(self):
        allow_list_entries = []
        block_list_entries = []
        closed_list = [
            "||status||ticket_id||ticket_type||entity||subdomains||malicious_reports||last_seen||categories||feed||source||filtered||cat_strength||confidence||resolution||response||"
        ]
        open_list = [
            "||status||ticket_id||ticket_type||entity||subdomains||malicious_reports||last_seen||categories||feed||source||filtered||cat_strength||confidence||resolution||response||"
        ]
        sorted_entities = sorted(self.entities, key=lambda x: x.ticket_id, reverse=False)
        for entity in sorted_entities:
            if entity.resolution.lower() == "in progress":
                line = f"|In Progress|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.subdomain_count}|{entity.positives}|{entity.last_seen}|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.is_filtered}|{entity.intel_category_strength}|{entity.resolution}|{entity.response}|"
                open_list.append(line)
            else:
                line = f"|Closed|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.subdomain_count}|{entity.positives}|{entity.last_seen}|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.is_filtered}|{entity.intel_category_strength}|{entity.resolution}|{entity.response}|"
                closed_list.append(line)

            if entity.resolution.lower() == "allow":
                allow_list_entries.append(
                    f"{entity.etp_domain},{entity.entity_type},ALL_TYPES_BEST_MATCH,no malicious indications,{self.time},Added by rballant,{entity.intel_source}"
                )
            if entity.resolution.lower() == "block":
                block_list_entries.append(
                    f"{entity.etp_domain},{entity.entity_type},{entity.attribution},Known,{entity.attribution_id},{entity.attribution_description},etp-manual,{self.time},added by rballant"
                )

        open_table = "\n".join(open_list)
        closed_table = "\n".join(closed_list)
        allow_strings = "\n".join(allow_list_entries)
        block_strings = "\n".join(block_list_entries)
        description = (
            " \n+{color:#de350b}*Please see the comment section to view open and closed cases.*{color}+\n\n\n"
            + "*Allow List*\n{code:java}\n"
            + allow_strings
            + "{code}"
            + "\n\n*Block List*\n{code:java}\n"
            + block_strings
            + "{code}"
        )

        headers = {"Content-Type": "application/json"}
        epoch = int(time.time())
        rdate = time.strftime("%Y-%m-%d", time.localtime(int(epoch)))
        subject_headline = f"Ticket Automation Results {rdate}"
        tmp_dict = {}
        tmp_dict["fields"] = {}
        tmp_dict["fields"]["project"] = {}
        tmp_dict["fields"]["project"]["key"] = "ETPESC"
        tmp_dict["fields"]["summary"] = subject_headline
        tmp_dict["fields"]["description"] = description
        tmp_dict["fields"]["issuetype"] = {}
        tmp_dict["fields"]["issuetype"]["name"] = "Assistance"
        tmp_dict["fields"]["components"] = [{"name": "Secops Automation"}]
        tmp_dict["fields"]["customfield_12703"] = "Internal"
        tmp_dict["fields"]["labels"] = ["ENT_SECOPS_OPERATIONS"]

        comment = (
            "*Open Cases*\n" + open_table + "\n\n\n*Closed Cases*\n" + closed_table
        )

        json_object = json.dumps(tmp_dict, indent=4)
        try:
            response = requests.post(
                jira_ticket_api,
                data=json_object,
                headers=headers,
                cert=(self.cert_path, self.key_path),
                verify=False
            )
        except Exception as e:
            logger.error(f"Failed to create ETP jira ticket - Error: {e}")
        else:
            issue_decoded = response.content.decode("utf-8")
            issue_json = json.loads(issue_decoded)
            issue = issue_json.get("key")
            status = str(response.status_code)
            if status.startswith("2"):
                logger.info(f"ETP ticket {issue} created succesfully")
                self.add_comment(self.queue, issue, comment, assignee="")
            else:
                logger.info(f"Failed to create ETP ticket {issue}. Status code: {status}")


    def close_ticket(self, ticket, resolved):
        # ENT_SECOPS_FALSE_POSITIVE
        logger.info(f"Resolving {ticket}")
        url = jira_ticket_api + f"{ticket}/transitions"

        headers = {"Content-Type": "application/json"}

        if resolved is True:
            payload = { "transition": {"id": "5"}}
        else:
            payload = { "transition": {"id": "4"}}

        try:
            response = requests.request(
                "PUT",
                url,
                data=payload,
                headers=headers,
                cert=(self.cert_path, self.key_path),
            )
        except Exception as e:
            logger.error(f"Failed to close {ticket} - Error: {e}")
        else:
            status = str(response.status_code)
            if status.startswith("2"):
                logger.info(f"Closed ticket {ticket}")
            else:
                logger.info(f"Failed to close {ticket}. Status code: {status}")


