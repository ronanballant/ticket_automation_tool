import csv
import json
import os
import time
from datetime import datetime, timedelta

import get_az_secret
import requests
from config import (automation_fqdn_results, automation_ticket_results,
                    blacklist_file, cert_name, cert_path, jira_ticket_api, key_name,
                    key_path, logger, previous_ticket_resolutions_path,
                    results_file_path, secops_member)
from intel_entry import IntelEntry
from ticket import Ticket


class TicketResponder:
    requests.packages.urllib3.disable_warnings(
        requests.urllib3.exceptions.InsecureRequestWarning
    )
    indicators = []
    service_type_sent = []
    resolved_tickets = []

    def __init__(self):
        self.assignee = secops_member
        self.label = ""
        self.time = int(time.time())
        self.cert_path = "processed_cert.crt"
        self.key_path = "processed_key.key"
        self.unresolved_file_path = (
            results_file_path + f"{self.time}_domains_to_analyse.csv"
        )
        self.response_file_path = results_file_path + f"{self.time}_result_comments.csv"
        self.get_username()
        self.get_keys()

    # def update_responder(self, ticket, indicators):
        # self.ticket = ticket
        # self.indicators = indicators
        # self.send_comment = False
        # self.ticket_resolved = True
        # self.block_comment = False
        # self.queue = self.indicators[0].queue
        # self.creation_time = self.indicators[0].creation_time
        # self.is_guardicore = self.indicators[0].is_guardicore_ticket
        # self.ticket_type = self.indicators[0].ticket_type
        # self.reporter = self.indicators[0].reporter
        # self.comment_greeting = f"Hi {self.reporter}\n\n"
        # self.comment_sign_off = "\n\nIf there are any further questions we will be happy to respond.\nSecOps Team"


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

    def update_ticket(self, ticket):
        self.ticket = ticket
        ticket.ticket_responses = ""
        self.current_time = datetime.now()
        self.time_to_response = ticket.time_to_response = (self.current_time - self.ticket.creation_time.replace(tzinfo=None))

        for indicator in ticket.indicators:
            indicator.insertion_timestamp = self.time
            indicator.time_to_response = self.time_to_response
            self.is_internal = indicator.is_internal

            if indicator.comment:
                ticket.ticket_responses = ticket.ticket_responses + f"\n\n{indicator.comment}"

            # TicketResponder.indicators.append(indicator)
            # self.save_indicator_details(indicator)
        
        # self.save_ticket_details()

        ticket.set_ticket_comment()
        if ticket.send_comment is True and ticket.block_comment is False:
            try:
                self.add_comment()
                ticket.comment_failed = False
                print(f"Responded to {ticket.ticket_id}")
                logger.info(f"Responded to {ticket.ticket_id}")
            except Exception as e:
                ticket.comment_failed = True
                print(f"Failed to respond to {ticket.ticket_id}: {e}")
                logger.info(f"Failed to respond to {ticket.ticket_id}: {e}")
        else:
            print(f"No resolution for {ticket.ticket_id} - Open to analyse")
            logger.info(f"No resolution for {ticket.ticket_id} - Open to analyse")

        # if ticket.ticket_resolved is True:
        #     TicketResponder.resolved_tickets.append(self.ticket)

        self.close_ticket()

        # os.remove(cert_path)
        # os.remove(key_path)

    def delete_indicator_details(self):
        os.remove(previous_ticket_resolutions_path)

    def create_sps_ticket(self, tickets):
        print("\nCreating SPS ticket")
        logger.info("Creating SPS ticket")
        
        for ticket in tickets:
            for indicator in ticket.indicators:
                TicketResponder.indicators.append(indicator)

        self.sorted_indicators = sorted(
            TicketResponder.indicators, key=lambda x: x.ticket.ticket_id, reverse=False
        )
        
        whitelist_additions = []
        blacklist_additions = []
        possible_changes = []
        closed_list = [
            "||ticket_id||ticket_type||fqdn||resolution||vt_indications||subdomains_in_intel||comments||categories||feed||source||confidence||vt_link||"
        ]
        open_list = [
            "||ticket_id||ticket_type||fqdn||resolution||vt_indications||subdomains_in_intel||comments||categories||feed||source||confidence||vt_link||"
        ]
        for indicator in self.sorted_indicators:
            self.process_attributes(indicator)
            self.queue = indicator.ticket.queue
            line = f"|{indicator.ticket.ticket_id}|{indicator.ticket.ticket_type}|{indicator.fqdn}|{indicator.indicator_resolution}|{indicator.vt_indications}|{indicator.subdomain_count}|{indicator.source_response} {indicator.rule_response}|{indicator.categories}|{indicator.intel_feed}|{indicator.intel_source}|{indicator.intel_confidence}|[Virus Total Link|{indicator.vt_link}]|"
            if indicator.indicator_resolution.lower() == "in progress":
                open_list.append(line)
                if indicator.ticket.ticket_type == "FP":
                    in_progress_line = f"+++ {indicator.fqdn},{indicator.ticket.ticket_id},whitelist"
                    intel_entry = IntelEntry(indicator, in_progress_line, "possible_changes", "add")
                    intel_entry.append_to_indicator()
                    possible_changes.append(in_progress_line)
                    indicator.ticket.possible_changes.append(in_progress_line)
                elif indicator.ticket.ticket_type == "FN":
                    in_progress_line = f"+++ {indicator.fqdn},{indicator.ticket.ticket_id},{indicator.attribution}"
                    intel_entry = IntelEntry(indicator, in_progress_line, "possible_changes", "add")
                    intel_entry.append_to_indicator()
                    possible_changes.append(in_progress_line)
                    indicator.ticket.possible_changes.append(in_progress_line)
            elif indicator.indicator_resolution.lower() == "allow":
                closed_list.append(line)
                whitelist_line = f"+++ {indicator.fqdn},{indicator.ticket.ticket_id},whitelist"
                intel_entry = IntelEntry(indicator, whitelist_line, "whitelist", "add")
                intel_entry.append_to_indicator()
                whitelist_additions.append(whitelist_line)
                indicator.ticket.whitelist_additions.append(whitelist_line)
            elif indicator.indicator_resolution.lower() == "block":
                closed_list.append(line)
                blacklist_line = f"+++ {indicator.fqdn},{indicator.ticket.ticket_id},{indicator.attribution}"
                intel_entry = IntelEntry(indicator, blacklist_line, "blacklist", "add")
                intel_entry.append_to_indicator()
                blacklist_additions.append(blacklist_line)
                indicator.ticket.blacklist_additions.append(blacklist_line)
            else: 
                closed_list.append(line)

        self.open_table = "\n".join(open_list)
        self.closed_table = "\n".join(closed_list)
        allow_strings = "\n".join(whitelist_additions)
        block_strings = "\n".join(blacklist_additions)
        possible_changes_strings = "\n".join(possible_changes)

        description_list = [
            " \n+{color:#de350b}*Please see the comment section to view open and closed cases.*{color}+\n\n"
        ]
        
        description_list.append("*Allow List*\n{code:java}")
        if whitelist_additions:
            description_list.append(allow_strings)
        description_list.append("{code}")

        description_list.append("\n*Block List*\n{code:java}")
        if blacklist_additions:
            description_list.append(block_strings)
        description_list.append("{code}")

        description_list.append("\n*Possible Intel Changes*\n{code:java}")
        if possible_changes:
            description_list.append(possible_changes_strings)
        description_list.append("{code}")

        description = "\n".join(description_list)

        headers = {"Content-Type": "application/json"}
        date = datetime.strftime(datetime.fromtimestamp(self.time), "%Y-%m-%d %H:00")
        
        # self.comment = (
        #     "*Open Cases*\n" + self.open_table + "\n\n\n*Closed Cases*\n" + self.closed_table
        # )

        data = {
            "fields": {
                "project": {"key": "RCSOR"},
                "summary": f"Ticket Automation Results {date}",
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
            self.summary_ticket_created = False
            logger.error(f"Failed to create SPS jira ticket - Error: {e}")
            print(f"\nFailed to create SPS jira ticket - Error: {e}\n")
        else:
            issue_decoded = response.content.decode("utf-8")
            issue_json = json.loads(issue_decoded)
            self.summary_ticket = issue_json.get("key")
            status = str(response.status_code)
            if status.startswith("2"):
                self.summary_ticket_created = True
                self.ticket = Ticket(self.summary_ticket, "Summary", "SPS", None, False, None, None, None, None)
                logger.info(f"SPS ticket {self.ticket.ticket_id} created succesfully")
                print(f"\nSPS ticket {self.ticket.ticket_id} created succesfully\n")
            else:
                self.summary_ticket_created = False
                logger.info(
                    f"Failed to create SPS ticket. Status code: {status}"
                )
                print(
                    f"\nFailed to create SPS ticket. Status code: {status}\n"
                )

            self.ticket.comment = (
                "*Open Cases*\n" + self.open_table + "\n\n\n*Closed Cases*\n" + self.closed_table
            )

    def create_etp_ticket(self, tickets):
        print("\nCreating ETP ticket")
        logger.info("Creating ETP ticket")
        whitelist_additions = []
        blacklist_removals = []
        blacklist_additions = []
        possible_changes = []
        closed_list = [
            "||Ticket ID||Ticket Type||FQDN||Resolution||VT Indications||Subdomains||Comments||VT Categories||Category||Source Feeds||Filtered||Filtered Reason||VT Link||"
        ]
        open_list = [
            "||Ticket ID||Ticket Type||FQDN||Resolution||VT Indications||Subdomains||Comments||VT Categories||Category||Source Feeds||Filtered||Filtered Reason||VT Link||"
        ]

        for ticket in tickets:
            for indicator in ticket.indicators:
                TicketResponder.indicators.append(indicator)

        self.sorted_indicators = sorted(
            TicketResponder.indicators, key=lambda x: x.ticket.ticket_id, reverse=False
        )



        for indicator in self.sorted_indicators:
            self.process_attributes(indicator)
            self.queue = indicator.ticket.queue
            line = f"|{indicator.ticket.ticket_id}|{indicator.ticket.ticket_type}|{indicator.fqdn}|{indicator.indicator_resolution}|{indicator.vt_indications}|{indicator.subdomain_count}|{indicator.source_response} {indicator.rule_response}|{indicator.categories}|{indicator.intel_category}|{indicator.intel_source_list}|{indicator.is_filtered}|{indicator.filter_reason}|[Virus Total Link|{indicator.vt_link}]|"
            if indicator.indicator_resolution.lower() == "in progress":
                open_list.append(line)
                if indicator.ticket.ticket_type == "FP":
                    self.get_single_intel_source(indicator)
                    in_progress_line = f"+++ {indicator.etp_fqdn},{indicator.indicator_type},ALL_TYPES_BEST_MATCH,no malicious indications,{str(self.time)},Added by {self.username},{indicator.single_intel_source}"
                    intel_entry = IntelEntry(indicator, in_progress_line, "possible_changes", "add")
                    intel_entry.append_to_indicator()
                    possible_changes.append(in_progress_line)
                    indicator.ticket.possible_changes.append(in_progress_line)
                    if indicator.is_in_man_bl is True:
                        self.find_manual_blacklist_entry(indicator)
                        in_progress_line = "--- " + self.manual_blacklist_entry
                        intel_entry = IntelEntry(indicator, in_progress_line, "possible_changes", "remove")
                        intel_entry.append_to_indicator()
                        possible_changes.append(in_progress_line)
                        indicator.ticket.possible_changes.append(in_progress_line)
                elif indicator.ticket.ticket_type == "FN":
                    in_progress_line = f"+++ {indicator.etp_fqdn},{indicator.indicator_type},{indicator.attribution},Known,{indicator.attribution_id},{indicator.attribution_description},etp-manual,{str(self.time)},added by {self.username}"
                    intel_entry = IntelEntry(indicator, in_progress_line, "possible_changes", "add")
                    intel_entry.append_to_indicator()
                    possible_changes.append(in_progress_line)
                    indicator.ticket.possible_changes.append(in_progress_line)
            elif indicator.indicator_resolution.lower() == "allow":
                closed_list.append(line)
                self.get_single_intel_source(indicator)
                whitelist_line = f"+++ {indicator.etp_fqdn},{indicator.indicator_type},ALL_TYPES_BEST_MATCH,no malicious indications,{str(self.time)},Added by {self.username},{indicator.single_intel_source}"
                intel_entry = IntelEntry(indicator, whitelist_line, "whitelist", "add")
                intel_entry.append_to_indicator()
                whitelist_additions.append(whitelist_line)
                indicator.ticket.whitelist_additions.append(whitelist_line)
                if indicator.is_in_man_bl is True:
                    self.find_manual_blacklist_entry(indicator)
                    blacklist_removals_line = "--- " + self.manual_blacklist_entry
                    intel_entry = IntelEntry(indicator, blacklist_removals_line, "blacklist", "remove")
                    intel_entry.append_to_indicator()
                    blacklist_removals.append(blacklist_removals_line)
                    indicator.ticket.blacklist_removals.append(blacklist_removals_line)
            elif indicator.indicator_resolution.lower() == "block":
                closed_list.append(line)
                blacklist_line = f"+++ {indicator.etp_fqdn},{indicator.indicator_type},{indicator.attribution},Known,{indicator.attribution_id},{indicator.attribution_description},etp-manual,{str(self.time)},added by {self.username}"
                intel_entry = IntelEntry(indicator, blacklist_line, "blacklist", "add")
                intel_entry.append_to_indicator()
                blacklist_additions.append(blacklist_line)
                indicator.ticket.blacklist_additions.append(blacklist_line)
            else: 
                closed_list.append(line)
            

        self.open_table = "\n".join(open_list)
        self.closed_table = "\n".join(closed_list)
        allow_strings = "\n".join(whitelist_additions) if whitelist_additions else ""
        block_strings = "\n".join(blacklist_additions) if blacklist_additions else ""
        remove_strings = "\n".join(blacklist_removals) if blacklist_removals else ""
        possible_changes_strings = "\n".join(possible_changes)

        description_list = [
            "\n+{color:#de350b}*Please see the comment section to view open and closed cases.*{color}+\n\n\n"
        ]

        description_list.append("*Manual Whitelist Changes*\n{code:java}")
        if whitelist_additions:
            description_list.append(allow_strings)
        description_list.append("{code}")

        description_list.append("\n*Manual Blacklist Changes*\n{code:java}")
        if blacklist_removals:
            description_list.append(remove_strings)
        if blacklist_additions:
            description_list.append(block_strings)
        description_list.append("{code}")

        description_list.append("\n*Possible Intel Changes*\n{code:java}")
        if possible_changes:
            description_list.append(possible_changes_strings)
        description_list.append("{code}")

        description = "\n".join(description_list)

        date = datetime.strftime(datetime.fromtimestamp(self.time) + timedelta(hours=2), "%Y-%m-%d %H:00")

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

        # self.comment = (
        #     "*Open Cases*\n" + self.open_table + "\n\n\n*Closed Cases*\n" + self.closed_table
        # )

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
            self.summary_ticket_created = False
            logger.error(f"Failed to create ETP jira ticket - Error: {e}")
            print(f"\nFailed to create ETP jira ticket - Error: {e}\n")
        else:
            issue_decoded = response.content.decode("utf-8")
            issue_json = json.loads(issue_decoded)
            self.summary_ticket = issue_json.get("key")
            status = str(response.status_code)
            if status.startswith("2"):
                self.summary_ticket_created = True
                self.ticket = Ticket(self.summary_ticket, "Summary", "ETP", None, False, None, None, None, None)
                print(f"\nETP ticket {self.summary_ticket} created succesfully\n")
                logger.info(f"ETP ticket {self.summary_ticket} created succesfully")
            else:
                self.summary_ticket_created = False
                logger.info(
                    f"Failed to create ETP ticket. Status code: {status}"
                )
                print(
                    f"\nFailed to create ETP ticket. Status code: {status}\n"
                )
            self.ticket.comment = (
                "*Open Cases*\n" + self.open_table + "\n\n\n*Closed Cases*\n" + self.closed_table
            )
            
            # try:
            #     self.add_comment()
            # except Exception as e:
            #     logger.info(f"Failed to add result comments to {self.summary_ticket}: {e}")
            #     print(f"\nFailed to add result comments to {self.summary_ticket}: {e}")

    def add_comment(self):
        logger.info(f"Adding comment to {self.ticket.ticket_id}")
        url = jira_ticket_api + self.ticket.ticket_id

        headers = {"Accept": "application/json", "Content-Type": "application/json"}

        if self.ticket.queue.lower() == "sps":
            if self.ticket.ticket_resolved is False:
                self.assignee = ""
            payload = {
                "update": {
                    "comment": [{"add": {"body": self.ticket.comment}}],
                    "assignee": [{"set": {"name": self.assignee}}],
                }
            }
        else:
            # payload = {
            #     "update": {
            #         "comment": [{"add": {"body": self.ticket.comment}}],
            #         "assignee": [{"set": {"name": self.assignee}}],
            #         "labels": [{"add": self.label}],
            #     }
            # }
            payload = {
                "update": {
                    "comment": [{"add": {"body": self.ticket.comment}}],
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

        if str(response.status_code).startswith("2"):
            self.comment_succesfully_added = True
        else:
            self.comment_succesfully_added = False

    def close_ticket(self):
        if self.ticket.queue == "SPS":
            ticket_in_progress = "4"
            ticket_resolved = "5"
            transitions = [ticket_in_progress, ticket_resolved]

            if (
                self.ticket.ticket_resolved is True 
                and self.ticket.requires_approval is False
                and self.ticket.comment_failed is False
                and self.ticket.block_comment is False
                and self.ticket.send_comment is True
            ):
                new_status = "Closed"
                print(f"Changing {self.ticket.ticket_id} status to '{new_status}'")
                logger.info(f"Changing {self.ticket.ticket_id} status to '{new_status}'")
                try:
                    self.transition_ticket(transitions)
                    pass
                except Exception as e:
                    print(f"Failed to close {self.ticket.ticket_id}: {e}")
                    logger.info(f"Failed to close {self.ticket.ticket_id}: {e}")
                else:
                    self.ticket.time_to_resolution = (self.current_time - self.ticket.creation_time.replace(tzinfo=None))
            else:
                print(f"Changing {self.ticket.ticket_id} status to 'In Progress'")
                logger.info(f"Changing {self.ticket.ticket_id} status to 'In Progress'")
                try:
                    self.transition_ticket(transitions[:-1])
                    pass
                except Exception as e:
                    print(f"Failed to change {self.ticket.ticket_id} status: {e}")
                    logger.info(f"Failed to change {self.ticket.ticket_id} status: {e}")
        else:
            ticket_triaged = "31"
            ticket_in_progress = "221"
            ticket_resolved = "141"
            transitions = [ticket_triaged, ticket_in_progress, ticket_resolved]

            if (
                self.ticket.ticket_resolved is True 
                and self.ticket.requires_approval is False
                and self.ticket.comment_failed is False
                and self.ticket.block_comment is False
            ):
                self.add_service_type()
                try:
                    print(f"Changing {self.ticket.ticket_id} status to 'Closed'")
                    logger.info(f"Updating {self.ticket.ticket_id} status to 'Closed'")
                    self.transition_ticket(transitions)
                except Exception as e:
                    print(f"Failed to close {self.ticket.ticket_id}: {e}")
                    logger.info(f"Failed to close {self.ticket.ticket_id}: {e}")
                else:
                    self.ticket.time_to_resolution = (self.current_time - self.ticket.creation_time.replace(tzinfo=None))
            else:
                try:
                    print(f"Changing {self.ticket.ticket_id} status to 'In Progress'")
                    logger.info(f"Updating {self.ticket.ticket_id} status to 'In Progress'")
                    self.transition_ticket(transitions[:-1])
                except Exception as e:
                    print(f"Failed to update {self.ticket.ticket_id} status: {e}")
                    logger.info(f"Failed to update {self.ticket.ticket_id} status: {e}")

    def process_attributes(self, indicator):
        for attribute, value in vars(indicator).items():
            if value is None:
                setattr(indicator, attribute, '-')

    def add_service_type(self):
        if self.ticket.ticket_id not in TicketResponder.service_type_sent:
            if self.ticket.ticket_type == "FP":
                if self.ticket.is_guardicore_ticket is True:
                    self.service_type = "GC_TRUE_POSITIVE_DOMAIN"
                else:
                    if self.is_internal is True:
                        self.service_type = "ESCR_TRUE_POSITIVE_INT_FEED"
                    else:
                        self.service_type = "ESCR_TRUE_POSITIVE_THIRD_PARTY"
            if self.ticket.ticket_type == "FN":
                if self.ticket.is_guardicore_ticket is True:
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

    def transition_ticket(self, transitions):
        url = jira_ticket_api + f"{self.ticket.ticket_id}/transitions"
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
                logger.error(f"Failed to transition {self.ticket.ticket_id} status - Error: {e}")
                print(f"\nFailed to update {self.ticket.ticket_id} status - Error: {e}\n")
                break
            else:
                status = str(response.status_code)
                if status.startswith("2"):
                    logger.info(f"Status updated succesfully")
                    print(f"Status updated succesfully")
                else:
                    logger.info(
                        f"Failed to update status {self.ticket.ticket_id}. Status code: {status}"
                    )
                    print(
                        f"\nFailed to update status {self.ticket.ticket_id}. Status code: {status}\n"
                    )
                    break

    def find_manual_blacklist_entry(self, indicator):
        self.manual_blacklist_entry = None
        try:
            with open(blacklist_file, "r") as file:
                reader = file.readlines()

            for line in reader:
                data = line.split(",") 
                if data[0] == f"{indicator.fqdn}.":
                    self.manual_blacklist_entry = line.strip()
                    break
            
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

    # def save_ticket_details(self):
    #     with open(automation_ticket_results,  mode="a", newline="") as f:
    #         writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_MINIMAL)
    #         writer.writerow(
    #             [
    #                 self.ticket.queue,
    #                 self.ticket.ticket_type,
    #                 self.ticket.ticket_id,
    #                 self.ticket.ticket_resolved,
    #                 self.time_to_response,
    #             ]
    #         )

    # def save_indicator_details(self, indicator):
    #     indicator_file_paths = [previous_ticket_resolutions_path, indicators_in_progress]
    #     for path in indicator_file_paths:
    #         with open(path,  mode="a+", newline="") as f:
    #             writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_MINIMAL)
    #             writer.writerow(
    #                 [
    #                     indicator.ticket.queue,
    #                     indicator.ticket.ticket_type,
    #                     indicator.ticket.ticket_id,
    #                     indicator.fqdn,
    #                     indicator.domain,
    #                     indicator.vt_indications,
    #                     indicator.subdomain_count,
    #                     indicator.ticket.creation_time,
    #                     indicator.time_to_response,
    #                     indicator.indicator_resolution,
    #                     indicator.ticket.ticket_resolved,
    #                     indicator.source_response,
    #                     indicator.rule_response,
    #                     indicator.days_since_last_scanned,
    #                     indicator.categories,
    #                     indicator.intel_feed,
    #                     indicator.intel_source,
    #                     indicator.intel_confidence,
    #                     indicator.attribution,
    #                     indicator.ticket.requires_approval,
    #                 ]
    #             )


    # def find_manual_blacklist_entry(self, indicator):
    #     updated_lines = []
    #     self.manual_blacklist_entry = None
    #     try:
    #         with open(blacklist_file, "r") as file:
    #             reader = file.readlines()

    #         for line in reader:
    #             data = line.split(",") 
    #             if data[0] == f"{indicator.fqdn}.":
    #                 self.manual_blacklist_entry = line 
    #             else:
    #                 updated_lines.append(line)

    #         with open(blacklist_file, 'w', newline="") as file:
    #             writer = csv.writer(file)
    #             writer.writerows(updated_lines)
            
    #         print(f"{self.manual_blacklist_entry} removed from the blacklist")
    #         logger.info(f"{self.manual_blacklist_entry} removed from the blacklist")
    #     except FileNotFoundError:
    #         print(f"Error: File '{blacklist_file}' not found.")
    #     except Exception as e:
    #         print(f"An unexpected error occurred: {e}")