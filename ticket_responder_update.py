import csv
import json
import os
import time
from datetime import datetime
import requests

import get_az_secret
from config import logger
from ticket import Ticket


class TicketResponder:
    requests.packages.urllib3.disable_warnings(
        requests.urllib3.exceptions.InsecureRequestWarning
    )
    indicators = []
    service_type_sent = []
    resolved_tickets = []

    def __init__(self, cert_path, key_path, jira_ticket_api, secops_member="rballant"):
        self.assignee = secops_member
        self.time = int(time.time())
        self.cert_path = "processed_cert.crt"
        self.key_path = "processed_key.key"
        self.get_username()
        self.get_keys()

    def get_username(self):
        self.username = os.getenv("USER") or os.getenv("USERNAME")

    def add_comment(self, ticket):
        self.ticket = ticket
        logger.info(f"Adding comment to {self.ticket.ticket_id}")
        url = self.jira_ticket_api + self.ticket.ticket_id

        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        if self.ticket.queue.lower() == "sps":
            payload = {
                "update": {
                    "comment": [{"add": {"body": self.ticket.comment}}],
                    "assignee": [{"set": {"name": self.assignee}}],
                }
            }
        else:
            payload = {
                "update": {
                    "comment": [{"add": {"body": self.ticket.comment}}],
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

    def transition_ticket(self, ticket, transition):
        self.ticket = ticket
        if self.ticket.queue == "SPS":
            ticket_in_progress = "4"
            ticket_resolved = "5"

            if transition.lower() == "in progress":
                transitions = [ticket_in_progress]
            
            if transition.lower() == "close":
                transitions = [ticket_in_progress, ticket_resolved]
        else:
            ticket_triaged = "31"
            ticket_in_progress = "221"
            ticket_resolved = "141"

            if transition.lower() == "in progress":
                transitions = [ticket_triaged, ticket_in_progress]
            
            if transition.lower() == "close":
                transitions = [ticket_triaged, ticket_in_progress, ticket_resolved]


        url = self.jira_ticket_api + f"{self.ticket.ticket_id}/transitions"
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
                logger.error(f"Failed to transition {ticket.ticket_id} status - Error: {e}")
                print(f"\nFailed to update {ticket.ticket_id} status - Error: {e}\n")
                break
            else:
                status = str(response.status_code)
                if status.startswith("2"):
                    logger.info(f"Status changed to {transition}")
                    print(f"Status changed to {transition}")
                else:
                    logger.info(f"Failed to update status {self.ticket.ticket_id}. Status code: {status}")
                    print(f"\nFailed to update status {self.ticket.ticket_id}. Status code: {status}\n")
                    break

    def create_ticket(self, ticket):
        self.ticket = ticket
        print(f"\nCreating {ticket.queue} ticket")
        logger.info(f"Creating {ticket.queue} ticket")

        headers = {"Content-Type": "application/json"}
        date = datetime.strftime(datetime.fromtimestamp(self.time), "%Y-%m-%d %H:00")
        data = {
            "fields": {
                "project": {"key": "RCSOR"},
                "summary": f"Ticket AUtomation Results {date}",
                "description": ticket.summary_decription,
                "issuetype": {"name": "Task"},
            }
        }

        try:
            response = requests.post(
                self.jira_ticket_api,
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
            self.summary_ticket = issue_json.get("key")
            status = str(response.status_code)
            if status.startswith("2"):
                self.ticket = Ticket(self.summary_ticket, "Summary", "SPS", None, False, None, None, None, None)
                logger.info(f"SPS ticket {self.ticket.ticket_id} created succesfully")
                print(f"\nSPS ticket {self.ticket.ticket_id} created succesfully\n")
            else:
                logger.info(f"Failed to create SPS ticket. Status code: {status}")
                print(f"\nFailed to create SPS ticket. Status code: {status}\n")

            self.ticket.comment = (
                "*Open Cases*\n" + open_table + "\n\n\n*Closed Cases*\n" + closed_table
            )
            try:
                self.add_comment()
            except Exception as e:
                logger.info(f"Failed to add result comments to {self.summary_ticket}: {e}")
                print(f"\nFailed to add result comments to {self.summary_ticket}: {e}")

    def create_etp_ticket(self):
        print("\nCreating ETP ticket")
        logger.info("Creating ETP ticket")
        whitelist_additions = []
        blacklist_removals = []
        blacklist_additions = []
        possible_changes = []

        closed_list = [
            "||ticket_id||ticket_type||fqdn||resolution||vt_indications||subdomains||comments||categories||feed||source||filtered||cat_strength||vt_link||"
        ]
        open_list = [
            "||ticket_id||ticket_type||fqdn||resolution||vt_indications||subdomains||comments||categories||feed||source||filtered||cat_strength||vt_link||"
        ]
        self.sorted_indicators = sorted(
            TicketResponder.indicators, key=lambda x: x.ticket.ticket_id, reverse=False
        )

        for indicator in self.sorted_indicators:
            self.process_attributes(indicator)
            self.queue = indicator.ticket.queue
            line = f"|{indicator.ticket.ticket_id}|{indicator.ticket.ticket_type}|{indicator.fqdn}|{indicator.indicator_resolution}|{indicator.vt_indications}|{indicator.subdomain_count}|{indicator.source_response} {indicator.rule_response}|{indicator.categories}|{indicator.intel_feed}|{indicator.intel_source}|{indicator.is_filtered}|{indicator.intel_category_strength}|[Virus Total Link|{indicator.vt_link}]|"
            if indicator.indicator_resolution.lower() == "in progress":
                open_list.append(line)
                if indicator.ticket.ticket_type == "FP":
                    in_progress_data = [
                        indicator.etp_fqdn,
                        indicator.indicator_type,
                        "ALL_TYPES_BEST_MATCH",
                        "no malicious indications",
                        str(self.time),
                        f"Added by {self.username}",
                        indicator.single_intel_source
                    ]

                    in_progress_line = "+++ " + ",".join(in_progress_data)
                    possible_changes.append(in_progress_line)
                    indicator.ticket.possible_changes.append(in_progress_line)

                    if indicator.is_in_man_bl is True:
                        self.find_manual_blacklist_entry(indicator)
                        in_progress_line = "--- " + self.manual_blacklist_entry
                        possible_changes.append(in_progress_line)
                        indicator.ticket.possible_changes.append(in_progress_line)
                elif indicator.ticket.ticket_type == "FN":
                    in_progress_data = [
                        indicator.etp_fqdn,
                        indicator.indicator_type,
                        indicator.attribution,
                        "Known",
                        indicator.attribution_id,
                        indicator.attribution_description,
                        "etp-manual",
                        str(self.time),
                        f"added by {self.username}"
                    ]

                    in_progress_line = "+++ " + ",".join(in_progress_data)
                    possible_changes.append(in_progress_line)
                    indicator.ticket.possible_changes.append(in_progress_line)
            elif indicator.indicator_resolution.lower() == "allow":
                closed_list.append(line)
                self.get_single_intel_source(indicator)
                whitelist_data = [
                    indicator.etp_fqdn,
                    indicator.indicator_type,
                    "ALL_TYPES_BEST_MATCH",
                    "no malicious indications",
                    str(self.time),
                    f"Added by {self.username}",
                    indicator.single_intel_source
                ]

                whitelist_line = ",".join(whitelist_data)
                whitelist_additions.append(whitelist_line)
                indicator.ticket.whitelist_additions.append(whitelist_line)
                if indicator.is_in_man_bl is True:
                    self.find_manual_blacklist_entry(indicator)
                    blacklist_removals.append(self.manual_blacklist_entry)
                    indicator.ticket.blacklist_removals.append(self.manual_blacklist_entry)
            elif indicator.indicator_resolution.lower() == "block":
                closed_list.append(line)
                blacklist_data = [
                        indicator.etp_fqdn,
                        indicator.indicator_type,
                        indicator.attribution,
                        "Known",
                        indicator.attribution_id,
                        indicator.attribution_description,
                        "etp-manual",
                        str(self.time),
                        f"added by {self.username}"
                    ]
                blacklist_line = ",".join(blacklist_data)
                blacklist_additions.append(blacklist_line)
                indicator.ticket.blacklist_additions.append(blacklist_line)
            else: 
                closed_list.append(line)
            

        open_table = "\n".join(open_list)
        closed_table = "\n".join(closed_list)
        allow_strings = "\n+++ " + "\n+++ ".join(whitelist_additions)
        block_strings = "\n+++ " + "\n+++ ".join(blacklist_additions)
        remove_strings = "\n--- " + "\n--- ".join(blacklist_removals)
        possible_changes_strings = "\n".join(possible_changes)

        description_list = [
            "\n+{color:#de350b}*Please see the comment section to view open and closed cases.*{color}+\n\n\n"
        ]

        if whitelist_additions:
            # description_list.append("*Manual Whitelist Changes*\n{code:java}")
            description_list.append("*Manual Whitelist Changes*\n{code:java}")
            description_list.append(allow_strings)
            description_list.append("{code}")

        if blacklist_additions or blacklist_removals:
            description_list.append("\n*Manual Blacklist Changes*\n{code:java}")
            description_list.append(remove_strings)
            description_list.append(block_strings)
            description_list.append("{code}")

        if possible_changes:
            description_list.append("\n*Possible Intel Changes*\n{code:java}")
            description_list.append(possible_changes_strings)
            description_list.append("{code}")

        description = "\n".join(description_list)

        print(description)

        date = datetime.strftime(datetime.fromtimestamp(self.time), "%Y-%m-%d %H:00")

        headers = {"Content-Type": "application/json"}
        subject_headline = f"Ticket Automation Results {date}"
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
            self.summary_ticket = issue_json.get("key")
            status = str(response.status_code)
            if status.startswith("2"):
                print(f"\nETP ticket {self.summary_ticket} created succesfully\n")
                logger.info(f"ETP ticket {self.summary_ticket} created succesfully")
            else:
                logger.info(
                    f"Failed to create ETP ticket. Status code: {status}"
                )
                print(
                    f"\nFailed to create ETP ticket. Status code: {status}\n"
                )
            try:
                self.add_comment()
            except Exception as e:
                logger.info(f"Failed to add result comments to {self.summary_ticket}: {e}")
                print(f"\nFailed to add result comments to {self.summary_ticket}: {e}")

            # self.delete_indicator_details()

    

    def process_attributes(self, indicator):
        for attribute, value in vars(indicator).items():
            if value is None:
                setattr(indicator, attribute, '-')

    def add_service_type(self):
        if self.ticket.ticket_id not in TicketResponder.service_type_sent:
            if self.ticket.ticket_type == "FP":
                if self.ticket.is_guardicore is True:
                    self.service_type = "GC_TRUE_POSITIVE_DOMAIN"
                else:
                    if self.is_internal is True:
                        self.service_type = "ESCR_TRUE_POSITIVE_INT_FEED"
                    else:
                        self.service_type = "ESCR_TRUE_POSITIVE_THIRD_PARTY"
            if self.ticket.ticket_type == "FN":
                if self.ticket.is_guardicore is True:
                    self.service_type = "GC_TRUE_NEGATIVE_DOMAIN"
                else:
                    self.service_type = "ESCR_TRUE_NEGATIVE_GENERIC"

            url = jira_ticket_api + f"{self.ticket.ticket_id}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "update": {"customfield_17300": [{"set": {"value": self.service_type}}]}
            }

            print(f"Adding service type")
            logger.info(f"Adding service type {self.ticket.ticket_id}")
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
                    TicketResponder.service_type_sent.append(self.ticket.ticket_id)
                else:
                    print(
                        f"\nFailed to add service type to {self.ticket.ticket_id}. Status code: {status}"
                    )
                    logger.error(
                        f"Failed to add service type to {self.ticket.ticket_id}. Status code: {status}"
                    )

    def find_manual_blacklist_entry(self, indicator):
        self.manual_blacklist_entry = None
        try:
            with open(blacklist_file, "r") as file:
                reader = file.readlines()

            for line in reader:
                data = line.split(",") 
                if data[0] == f"{indicator.fqdn}.":
                    self.manual_blacklist_entry = line 
            
            print(f"{self.manual_blacklist_entry} removed from the blacklist")
            logger.info(f"{self.manual_blacklist_entry} removed from the blacklist")
        except FileNotFoundError:
            print(f"Error: File '{blacklist_file}' not found.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def get_single_intel_source(self, indicator):
        intel_sources = [entry.strip() for entry in indicator.intel_source.split(",")]
        source_found = False
        
        for source in intel_sources:
            if "manual" in source.lower():
                indicator.single_intel_source = source
                source_found = True
        
        if source_found is False:
            for source in intel_sources:
                if 'partial' not in source.lower() and 'risky' not in source.lower():
                    indicator.single_intel_source = source
                    source_found = True
            
        if source_found is False:
            indicator.single_intel_source = intel_sources[0]

    def save_ticket_details(self):
        with open(automation_ticket_results,  mode="a", newline="") as f:
            writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_MINIMAL)
            writer.writerow(
                [
                    self.ticket.queue,
                    self.ticket.ticket_type,
                    self.ticket.ticket_id,
                    self.ticket.ticket_resolved,
                    self.time_to_response,
                ]
            )

    def save_indicator_details(self, indicator):
        with open(previous_ticket_resolutions_path,  mode="a", newline="") as f:
            writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_MINIMAL)
            writer.writerow(
                [
                    indicator.ticket.queue,
                    indicator.ticket.ticket_type,
                    indicator.ticket.ticket_id,
                    indicator.fqdn,
                    indicator.domain,
                    indicator.vt_indications,
                    indicator.subdomain_count,
                    indicator.ticket.creation_time,
                    indicator.time_to_response,
                    indicator.indicator_resolution,
                    indicator.source_response,
                    indicator.rule_response,
                    indicator.days_since_last_scanned,
                    indicator.categories,
                    indicator.intel_feed,
                    indicator.intel_source,
                    indicator.intel_confidence,
                    indicator.attribution,
                ]
            )
