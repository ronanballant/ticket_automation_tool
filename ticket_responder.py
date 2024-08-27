import csv
import json
import os
import time


import requests

import get_az_secret
from config import (cert_name, cert_path, jira_ticket_api, key_name, key_path,
                    logger, results_file_path, secops_member)
from entity import Entity


class TicketResponder:
    requests.packages.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
    entities = []
    service_type_sent = []
    resolved_tickets = []

    def __init__(self):
        self.assignee = secops_member
        self.label = ''
        self.time = int(time.time())
        self.cert_path = "processed_cert.crt"
        self.key_path = "processed_key.key"
        self.unresolved_file_path = results_file_path + f"{self.time}_domains_to_analyse.csv"
        self.response_file_path = results_file_path + f"{self.time}_result_comments.csv"
        self.get_username()
        self.get_keys()

    def update_responder(self, ticket, entities):
        self.ticket = ticket
        self.entities = entities

    def get_username(self):
        self.username = os.getenv("USER") or os.getenv("USERNAME")

    def get_keys(self):
        with open(cert_path, "r") as f:
            cert = f.readlines()

        with open(self.cert_path, "w") as f:
            for line in cert:
                f.write(line.replace("\\n", "\n").replace("\n ", "\n"))

        with open(key_path, "r") as f:
            key = f.readlines()

        with open(self.key_path, "w") as f:
            for line in key:
                f.write(line.replace("\\n", "\n").replace("\n ", "\n"))

    # def get_keys(self):
    #     cert = get_az_secret.get_az_secret(cert_name)
    #     self.cert_path = cert_path
    #     with open(self.cert_path, "w") as f:
    #         f.write(cert.replace("\\n", "\n").replace("\n ", "\n"))
    #     key = get_az_secret.get_az_secret(key_name)
    #     self.key_path = key_path
    #     with open(self.key_path, "w") as f:
    #         f.write(key.replace("\\n", "\n").replace("\n ", "\n"))

    def update_ticket(self):
        send_comment = False
        self.ticket_resolved = True
        self.queue = self.entities[0].queue
        self.is_guardicore = self.entities[0].is_guardicore_ticket
        self.ticket_type = self.entities[0].ticket_type
        self.reporter = self.entities[0].reporter
        greeting = f"Hi {self.reporter}\n\n"
        end = "\n\nIf there are any further questions we will be happy to respond.\nSecOPs Team"
        ticket_responses = ''
        for entity in self.entities:
            self.save_entity_details(entity)
            self.is_internal = entity.is_internal
            if entity.comment:
                ticket_responses = ticket_responses + f"\n\n{entity.comment}"
                if "is currently under investigation" in ticket_responses:
                    self.ticket_resolved = False
                else:
                    send_comment = True
            else:
                self.ticket_resolved = False

            TicketResponder.entities.append(entity)

        self.comment = greeting + ticket_responses + end
        if send_comment is True:
            try:
                self.add_comment()
                print(f"Responded to {self.ticket}")
                logger.info(f"Responded to {self.ticket}")
            except Exception as e:
                self.comment_sent = False
                self.comment_failed = True
                print(f"Failed to respond to {self.ticket}: {e}")
                logger.info(f"Failed to respond to {self.ticket}: {e}")     
            pass
        else:
            print(f"No resolution for {self.ticket} - Open to analyse")
            logger.info(f"No resolution for {self.ticket} - Open to analyse")

        if self.ticket_resolved is True:
            TicketResponder.resolved_tickets.append(self.ticket)

        self.close_ticket()

        # os.remove(cert_path)
        # os.remove(key_path)

    def save_entity_details(self, entity):
        with open("/Users/rballant/coding/projects/jira_ticket_process update/results/previous_entites.csv", "a") as f:
            file = csv.writer(f)
            file.writerow([
                entity.queue,
                entity.domain,
                entity.entity_type,
                entity.urls,
                entity.ticket_id,
                entity.ticket_type,
                entity.reporter,
                entity.entity,
                entity.positives,
                entity.subdomain_count,
                entity.days_since_last_seen,
                entity.categories,
                entity.intel_feed,
                entity.intel_source,
                entity.intel_confidence,
                entity.resolution,
                entity.source_response,
                entity.response,
                entity.vt_link,
                entity.resolution,
                entity.attribution,
            ])
        
    def delete_entity_details(self):
        os.remove("/Users/rballant/coding/projects/jira_ticket_process update/results/previous_entites.csv")
    
    def read_previous_entities(self):
        if os.path.exists("/Users/rballant/coding/projects/jira_ticket_process update/results/previous_entites.csv"):
            with open("/Users/rballant/coding/projects/jira_ticket_process update/results/previous_entites.csv", "r") as f:
                file = csv.reader(f)

                for row in file:
                    queue = row[0]
                    domain = row[1] 
                    entity_type = row[2] 
                    urls = list(row[3])
                    ticket = row[4] 
                    ticket_type = row[5] 
                    reporter = row[6]
                    entity = row[7]
                    positives = row[8]
                    subdomain_count = row[9]
                    days_since_last_seen = row[10]
                    categories = row[11]
                    intel_feed = row[12]
                    intel_source = row[13]
                    intel_confidence = row[14]
                    resolution = row[15]
                    source_response = row[16]
                    response = row[17]
                    vt_link = row[18]
                    resolution = row[19]
                    attribution = row[20]

                    entity = Entity(queue, domain, entity_type, urls, ticket, ticket_type, reporter, False, None)
                    entity.positives = positives
                    entity.subdomain_count = subdomain_count
                    entity.days_since_last_seen = days_since_last_seen
                    entity.categories = categories
                    entity.intel_feed = intel_feed
                    entity.intel_source = intel_source
                    entity.intel_confidence = intel_confidence
                    entity.resolution = resolution
                    entity.source_response = source_response
                    entity.response = response
                    entity.vt_link = vt_link
                    entity.resolution = resolution
                    entity.attribution = attribution
                    TicketResponder.entities.append(entity)
        else:
            with open("/Users/rballant/coding/projects/jira_ticket_process update/results/previous_entites.csv", "w") as f:
                f.write("")
            
            self.read_previous_entities()
                    

    def create_sps_ticket(self):
        print("\nCreating SPS ticket")
        logger.info("Creating SPS ticket")
        allow_list_entries = []
        block_list_entries = []
        closed_list = [
            "||status||ticket_id||ticket_type||entity||malicious reports||subdomains||last_analysed||categories||feed||source||confidence||resolution||response||vt_link||"
        ]
        open_list = [
            "||status||ticket_id||ticket_type||entity||malicious reports||subdomains||last_analysed||categories||feed||source||confidence||resolution||response||vt_link||"
        ]
        self.sorted_entities = sorted(
            TicketResponder.entities, key=lambda x: x.ticket_id, reverse=False
        )
        for entity in self.sorted_entities:
            self.queue = entity.queue
            if entity.resolution.lower() == "in progress":
                line = f"|In Progress|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.positives}|{entity.subdomain_count}|{entity.days_since_last_seen} days ago|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.intel_confidence}|{entity.resolution}|{entity.source_response} {entity.response}|[Virus Total Link|{entity.vt_link}]|"
                open_list.append(line)
            else:
                line = f"|Closed|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.positives}|{entity.subdomain_count}|{entity.days_since_last_seen} days ago|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.intel_confidence}|{entity.resolution}|{entity.source_response} {entity.response}|[Virus Total Link|{entity.vt_link}]|"
                closed_list.append(line)

            if entity.resolution.lower() == "allow":
                allow_list_entries.append(f"{entity.entity},{entity.ticket_id}")
            if entity.resolution.lower() == "block":
                block_list_entries.append(
                    f"{entity.entity},{entity.ticket_id},{entity.attribution}"
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

        try:
            response = requests.post(
                jira_ticket_api,
                json=data,
                headers=headers,
                cert=(self.cert_path, self.key_path),
                verify=False,
            )
        except Exception as e:
            logger.error(f"Failed to create SPS jira ticket - Error: {e}")
            print(f"\nFailed to create SPS jira ticket - Error: {e}\n")
        else:
            issue_decoded = response.content.decode("utf-8")
            issue_json = json.loads(issue_decoded)
            self.ticket = issue_json.get("key")
            status = str(response.status_code)
            if status.startswith("2"):
                logger.info(f"SPS ticket {self.ticket} created succesfully")
                print(f"\nSPS ticket {self.ticket} created succesfully\n")
            else:
                logger.info(f"Failed to create ETP ticket {self.ticket}. Status code: {status}")
                print(f"\nFailed to create ETP ticket {self.ticket}. Status code: {status}\n")
                
            self.comment = ("*Open Cases*\n" + open_table + "\n\n\n*Closed Cases*\n" + closed_table)
            try:
                self.add_comment()
            except Exception as e:
                logger.info(f"Failed to add result comments to {self.ticket}: {e}")
                print(f"\nFailed to add result comments to {self.ticket}: {e}")
            self.delete_entity_details()
            
    def create_etp_ticket(self):
        print("\nCreating ETP ticket")
        logger.info("Creating ETP ticket")
        allow_list_entries = []
        remove_list_entries = []
        block_list_entries = []
        closed_list = [
            "||status||ticket_id||ticket_type||entity||malicious reports||subdomains||last_analysed||categories||feed||source||filtered||cat_strength||confidence||resolution||response||vt_link||"
        ]
        open_list = [
            "||status||ticket_id||ticket_type||entity||malicious reports||subdomains||last_analysed||categories||feed||source||filtered||cat_strength||confidence||resolution||response||vt_link||"
        ]
        self.sorted_entities = sorted(
            TicketResponder.entities, key=lambda x: x.ticket_id, reverse=False
        )
        for entity in self.sorted_entities:
            self.queue = entity.queue
            if entity.resolution.lower() == "in progress":
                line = f"|In Progress|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.positives}|{entity.subdomain_count}|{entity.days_since_last_seen} days ago|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.is_filtered}|{entity.intel_category_strength}|{entity.resolution}|{entity.response}|[Virus Total Link|{entity.vt_link}]|"
                open_list.append(line)
            else:
                line = f"|Closed|{entity.ticket_id}|{entity.ticket_type}|{entity.entity}|{entity.positives}|{entity.subdomain_count}|{entity.days_since_last_seen} days ago|{entity.categories}|{entity.intel_feed}|{entity.intel_source}|{entity.is_filtered}|{entity.intel_category_strength}|{entity.resolution}|{entity.response}|[Virus Total Link|{entity.vt_link}]|"
                closed_list.append(line)

            if entity.resolution.lower() == "allow":
                allow_list_entries.append(
                    f"{entity.etp_domain},{entity.entity_type},ALL_TYPES_BEST_MATCH,no malicious indications,{self.time},Added by {self.username},{entity.intel_source}"
                )
                if entity.is_in_man_bl is True:
                    remove_list_entries.append(entity.etp_domain)
            if entity.resolution.lower() == "block":
                block_list_entries.append(
                    f"{entity.etp_domain},{entity.entity_type},{entity.attribution},Known,{entity.attribution_id},{entity.attribution_description},etp-manual,{self.time},added by {self.username}"
                )

        open_table = "\n".join(open_list)
        closed_table = "\n".join(closed_list)
        allow_strings = "\n".join(allow_list_entries)
        remove_strings = "\n".join(remove_list_entries)
        block_strings = "\n".join(block_list_entries)
        description_list = ["\n+{color:#de350b}*Please see the comment section to view open and closed cases.*{color}+\n\n\n"]
        if allow_list_entries:
            description_list.append("*Allow List*\n{code:java}")
            description_list.append(allow_strings)
            description_list.append("{code}")
        if remove_list_entries:
            description_list.append("\n*Remove from Manual Blacklist*\n{code:java}")
            description_list.append(remove_strings)
            description_list.append("{code}")
        if block_list_entries:
            description_list.append("\n*Block List*\n{code:java}")
            description_list.append(block_strings)
            description_list.append("{code}")
        
        description = "\n".join(description_list)

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

        self.comment = (
            "*Open Cases*\n" + open_table + "\n\n\n*Closed Cases*\n" + closed_table
        )
        json_object = json.dumps(tmp_dict, indent=4)
        try:
            response = requests.post(
                jira_ticket_api,
                data=json_object,
                headers=headers,
                cert=(self.cert_path, self.key_path),
                verify=False,
            )
        except Exception as e:
            logger.error(f"Failed to create ETP jira ticket - Error: {e}")
            print(f"\nFailed to create ETP jira ticket - Error: {e}\n")
        else:
            issue_decoded = response.content.decode("utf-8")
            issue_json = json.loads(issue_decoded)
            self.ticket = issue_json.get("key")
            status = str(response.status_code)
            if status.startswith("2"):
                print(f"\nETP ticket {self.ticket} created succesfully\n")
                logger.info(f"ETP ticket {self.ticket} created succesfully")
            else:
                logger.info(f"Failed to create ETP ticket {self.ticket}. Status code: {status}")
                print(f"\nFailed to create ETP ticket {self.ticket}. Status code: {status}\n")
            try:
                self.add_comment()
            except Exception as e:
                logger.info(f"Failed to add result comments to {self.ticket}: {e}")
                print(f"\nFailed to add result comments to {self.ticket}: {e}")
            
            self.delete_entity_details()

    def add_comment(self):
        logger.info(f"Adding comment to {self.ticket}")
        url = jira_ticket_api + self.ticket

        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        if self.queue.lower() == "sps":
            payload = {
                "update": {
                    "comment": [{"add": {"body": self.comment}}],
                    "assignee": [{"set": {"name": self.assignee}}],
                }
            }
        else:
            payload = {
                "update": {
                    "comment": [{"add": {"body": self.comment}}],
                    "assignee": [{"set": {"name": self.assignee}}],
                    "labels": [{"add": self.label}],
                }
            }

        response = requests.request(
            "PUT",
            url,
            json=payload,
            headers=headers,
            cert=(self.cert_path, self.key_path),
            verify=False,
        )

    def close_ticket(self):
        if self.queue == 'SPS':
            ticket_in_progress = "4"
            ticket_resolved = "5"
            transitions = [ticket_in_progress, ticket_resolved]

            if self.ticket_resolved is True:
                print(f"Closing {self.ticket}")
                logger.info(f"Closing {self.ticket}")
                try:
                    self.transition_ticket(transitions)
                except Exception as e:
                    print(f"Failed to close {self.ticket}: {e}")
                    logger.info(f"Failed to close {self.ticket}: {e}")
            else:
                print(f"Updating {self.ticket} status to 'In Progress'")
                logger.info(f"Updating {self.ticket} status to 'In Progress'")
                try:
                    self.transition_ticket(transitions[:-1])
                except Exception as e:
                    print(f"Failed to update {self.ticket} status: {e}")
                    logger.info(f"Failed to update {self.ticket} status: {e}")
        else:
            ticket_triaged = "31"
            ticket_in_progress = "221"
            # ticket_resolved = "141"
            transitions = [ticket_triaged, ticket_in_progress]

            if self.ticket_resolved is True:
                self.add_service_type()
                try:
                    print(f"Updating {self.ticket} status to 'In Progress'")
                    logger.info(f"Updating {self.ticket} status to 'In Progress'")
                    self.transition_ticket(transitions)
                except Exception as e:
                    print(f"Failed to update {self.ticket} status: {e}")
                    logger.info(f"Failed to update {self.ticket} status: {e}")
            else:
                try:
                    print(f"Updating {self.ticket} status to 'In Progress'")
                    logger.info(f"Updating {self.ticket} status to 'In Progress'")
                    self.transition_ticket(transitions)
                except Exception as e:
                    print(f"Failed to update {self.ticket} status: {e}")
                    logger.info(f"Failed to update {self.ticket} status: {e}")

    def add_service_type(self):
        if self.ticket_id not in TicketResponder.service_type_sent:
            if self.ticket_type == 'FP':
                if self.is_guardicore is True:
                        self.service_type = "GC_TRUE_POSITIVE_DOMAIN"
                else:
                    if self.is_internal is True:
                        self.service_type = "ESCR_TRUE_POSITIVE_INT_FEED"
                    else:
                        self.service_type = "ESCR_TRUE_POSITIVE_THIRD_PARTY"
            if self.ticket_type == 'FN':
                if self.is_guardicore is True:
                    self.service_type = "GC_TRUE_NEGATIVE_DOMAIN"
                else:
                    self.service_type = "ESCR_TRUE_NEGATIVE_GENERIC"

            url = jira_ticket_api + f"{self.ticket}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "update": {
                    "customfield_17300": [{"set": {"value":self.service_type}}]
                    }
                }

            print(f"Adding service type")
            logger.info(f"Adding service type {self.ticket}")
            try:
                response = requests.put(
                    url,
                    json=payload,
                    headers=headers,
                    cert=(cert_path, key_path),
                    verify=False,
                )
                pass
            except Exception as e:
                print(f"Failed to add service type: {e}")
                logger.info(f"Failed to add service type: {e}")
            else:
                status = str(response.status_code)
                if status.startswith("2"):
                    TicketResponder.service_type_sent.append(self.ticket)
                else:
                    print(f"\nFailed to add service type to {self.ticket}. Status code: {status}")
                    logger.error(f"Failed to add service type to {self.ticket}. Status code: {status}")

    def transition_ticket(self, transitions):
        url = jira_ticket_api + f"{self.ticket}/transitions"
        headers = {"Content-Type": "application/json"}
        for transition in transitions:
            payload = {"transition": {"id": transition}}
            try:
                response = requests.post(
                    url,
                    json=payload,
                    headers=headers,
                    cert=(self.cert_path, self.key_path),
                    verify=False,
                )
                pass
            except Exception as e:
                logger.error(f"Failed to transition {self.ticket} status - Error: {e}")
                print(f"\nFailed to update {self.ticket} status - Error: {e}\n")
                break
            else:
                status = str(response.status_code)
                if status.startswith("2"):
                    logger.info(f"Status updated succesfully")
                    print(f"Status updated succesfully")
                else:
                    logger.info(f"Failed to update status {self.ticket}. Status code: {status}")
                    print(f"\nFailed to update status {self.ticket}. Status code: {status}\n")
                    break
