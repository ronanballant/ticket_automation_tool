import csv
import json
import time
import unicodedata
from typing import Dict, List
import Levenshtein 
from datetime import datetime
import requests
from config import cert_path, key_path, logger
from ticket import Ticket


class ApprovalFinder:
    requests.packages.urllib3.disable_warnings(
        requests.urllib3.exceptions.InsecureRequestWarning
    )
    processed_tickets = []
    intel_data_strings = []

    def __init__(
        self,
        tickets_in_progress_file: str,
        open_summary_tickets_file: str,
        processed_tickets_file: str,
        jira_search_api: str,
        jira_ticket_api: str
    ) -> None:
        self.tickets_in_progress_file: str = tickets_in_progress_file
        self.open_summary_tickets_file: str = open_summary_tickets_file
        self.processed_tickets_file: str = processed_tickets_file
        self.jira_search_api: str = jira_search_api
        self.jira_ticket_api: str = jira_ticket_api
        self.reviewed_intel_changes: List[str] = []
        self.reviewed_allow_list: List[str] = []
        self.reviewed_block_list: List[str] = []
        self.approved_tickets: List[str] = []
        self.unapproved_tickets: List[str] = []
        self.incomplete_tickets: List[str] = {}
        self.complete_tickets: List[str] = {}
        self.summary_ticket: str = ""
        self.comment_owner: str = ""
        self.update_triggered: bool = False
        self.intel_changes: Dict = {}
        self.tickets: List = []

    def open_current_tickets(self):
        with open(self.tickets_in_progress_file, "r") as file:
            self.ticket_data = json.load(file)

    def create_tickets(self):
        for ticket in self.ticket_data:
            summary_ticket = ticket.get("linked_summary_ticket", "")
            if summary_ticket in self.open_summary_tickets:
                Ticket.from_dict(ticket)

    def clear_processed_summary_ticket(self):
        new_tickets = [
            ticket
            for ticket in self.open_summary_tickets
            if ticket != self.summary_ticket
        ]

        with open(self.open_summary_tickets_file, "w") as file:
            writer = csv.writer(file)
            for ticket in new_tickets:
                writer.writerow([ticket])

    def get_open_summary_tickets(self):
        with open(self.open_summary_tickets_file, "r") as file:
            reader = csv.reader(file)
            self.open_summary_tickets = [ticket[0] for ticket in reader if ticket[0]]
            print(self.open_summary_tickets)

    def group_tickets(self):
        self.grouped_tickets = {}

        for ticket in Ticket.all_tickets:
            summary = ticket.linked_summary_ticket
            if summary not in self.grouped_tickets:
                self.grouped_tickets[summary] = []
            self.grouped_tickets[summary].append(ticket)
            self.summary_tickets = list(self.grouped_tickets.keys())
            pass

    def open_jira_ticket(self):
        if "rcsor" in self.summary_ticket.lower():
            self.queue = "SPS"
        else:
            self.queue = "ETP"

        try:
            if self.queue.lower() == "sps":
                jql_query = f'project="ReCat Sec Ops Requests" AND issue = "{self.summary_ticket}"'

            if self.queue.lower() == "etp":
                jql_query = f'project="ETPESC" AND issue = "{self.summary_ticket}"'
            params = {"jql": jql_query, "maxResults": 100}

            self.req = requests.get(
                self.jira_search_api,
                params=params,
                cert=(cert_path, key_path),
                verify=False,
            )
        except Exception as e:
            print(f"JIRA ticket API Failed: {e}")
            logger.error(f"JIRA ticket API Failed: {e}")
            raise

    def get_comments(self):
        comment_api = self.jira_ticket_api + self.summary_ticket + "/comment"

        comment_response = requests.get(
            comment_api, 
            cert=(cert_path, key_path),
            verify=False,
        )

        if str(comment_response.status_code).startswith("2"):
            comments = json.loads(comment_response.text)
            self.comments = comments.get('comments', [])
        
    def find_if_approved(self):
        self.intel_changes_approved = False
        self.approval_word = 'approved'
        for comment in self.comments:
            comment_text = comment.get("body", "")
            comment_words = comment_text.lower().strip().split()
            self.comment_owner = comment.get('author', {}).get('name', 'rballant')
            self.comment_owner_id = comment.get('author', {}).get('key', 'JIRAUSER72807')
            if len(comment_words) < 3:
                if any(Levenshtein.distance(self.approval_word, word) <= 1 for word in comment_words):
                    self.intel_changes_approved = True
                    logger.info(f"Changes approved by {self.comment_owner}")
                    logger.info(f"Approval comment: {comment_text}")
                    break

    def parse_reviewed_changes(self):
        self.description = (
            self.description.replace("{code:java}", "").replace("{code}", "").strip()
        )
        if "rcsor" in self.summary_ticket.lower():
            start_marker = "*Allow List*"
            block_marker = "*Block List*"
            end_marker = "*Possible Intel Changes*"
            start_index = self.description.find(start_marker)
            block_index = self.description.find(block_marker)
            end_index = self.description.find(end_marker)
            if end_index == -1:
                end_index = len(self.description)
        else:
            start_marker = "*Manual Whitelist Changes*"
            block_marker = "*Manual Blacklist Changes*"
            end_marker = "*Possible Intel Changes*"
            start_index = self.description.find(start_marker)
            block_index = self.description.find(block_marker)
            end_index = self.description.find(end_marker)
            if end_index == -1:
                end_index = len(self.description)

        extracted_text = self.description[start_index + len(start_marker) : block_index]
        extracted_list = extracted_text.split("\n")
        allow_list = [entry.strip() for entry in extracted_list if entry.strip()]
        extracted_text = self.description[block_index + len(block_marker) : end_index]
        extracted_list = extracted_text.split("\n")
        block_list = [entry.strip() for entry in extracted_list if entry.strip()]

        self.reviewed_allow_list = [
            line.strip()
            for line in allow_list
            if line
        ]

        self.reviewed_block_list = [
            line.strip()
            for line in block_list
            if line
        ]

    def find_if_resolved(self):
        self.process_summary_ticket = True
        if self.resolution_status.lower() in ["closed", "resolved"]:
            self.process_summary_ticket = False

    def parse_ticket(self):
        try:
            if self.req.status_code == 200:
                logger.info(f"Retrieved {self.summary_ticket}")
                logger.info(f"Parsing {self.summary_ticket}")
                result_dict = json.loads(self.req.text)
                issues = result_dict.get("issues")
                if issues:
                    for entry in issues:
                        fields = entry.get("fields")
                        if fields:
                            self.resolution_status = fields.get("status", {}).get("name", "")
                            reporter_data = fields.get("assignee", {})
                            if reporter_data:
                                full_name = reporter_data.get("displayName", "")
                                self.user_name = reporter_data.get("name", "")
                                self.analyst_name = full_name.split(" ")[0]
                                self.analyst_handle = "[~{}]".format(self.user_name)
                            else:
                                full_name = ""
                                self.user_name = ""
                                self.analyst_name = ""
                                self.analyst_handle = ""
                            description = fields.get("description", "")
                            normalized_description = unicodedata.normalize(
                                "NFKC", description
                            )
                            self.description = normalized_description
                            self.description = self.description.replace("\r", "")
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

    def find_approved_intel_changes(self):
        for ticket in self.tickets:
            if ticket.requires_approval is True:
                ticket.changes_approved = True
                for indicator in ticket.indicators:
                    indicator.is_approved = True
                    for intel_entry in indicator.intel_entries:
                        entry_found = False
                        entry_string = intel_entry.entry
                        entry_parts = entry_string.split(",")
                        entry_length = len(entry_parts)
                        entry_fqdn = entry_parts[0].strip()
                        
                        for reviewed_change_string in self.reviewed_allow_list:
                            reviewed_change_parts = reviewed_change_string.split(",")
                            reviewed_length = len(reviewed_change_parts)
                            if reviewed_length == entry_length:
                                reviewed_fqdn = reviewed_change_parts[0]
                                if entry_fqdn == reviewed_fqdn:
                                    entry_found = True
                                    intel_entry.is_approved = True
                                    self.update_owner(intel_entry, reviewed_change_string)
                                    if intel_entry.intel_list.lower() == "possible_changes":
                                        intel_entry.intel_list = "whitelist"
                                        indicator.reviewed_resolution = "Allow"
                                    else:
                                        indicator.reviewed_resolution = indicator.indicator_resolution

                                    self.generate_data_string(indicator)
                        
                        for reviewed_change_string in self.reviewed_block_list:
                            reviewed_change_parts = reviewed_change_string.split(",")
                            reviewed_length = len(reviewed_change_parts)
                            if reviewed_length == entry_length:
                                reviewed_fqdn = reviewed_change_parts[0]
                                if entry_fqdn == reviewed_fqdn:
                                    entry_found = True
                                    intel_entry.is_approved = True
                                    self.update_owner(intel_entry, reviewed_change_string)
                                    indicator.sps_feed = intel_entry.approved_intel_change.split(",")[-1]
                                    if intel_entry.intel_list.lower() == "possible_changes":
                                        intel_entry.intel_list = "blacklist"
                                        indicator.reviewed_resolution = "Block"
                                    else:
                                        indicator.reviewed_resolution = indicator.indicator_resolution
                                    self.generate_data_string(indicator)
                        
                        if entry_found is False:
                            intel_entry.is_approved = False
                            indicator.is_approved = False
                            ticket.changes_approved = False
    
    def update_owner(self, entry, reviewed_change):
        reviewed_change_parts = reviewed_change.strip().split(",")
        updated_changes = []
        for part in reviewed_change_parts:
            if "added by" in part.lower():
                part = f"added by {self.comment_owner}"
            updated_changes.append(part.strip())

        reviewed_change = ",".join(updated_changes)
        entry.approved_intel_change = reviewed_change

    def update_assignee(self, ticket_id):
        url = self.jira_ticket_api + f"{ticket_id}/assignee"
        headers = {"Content-Type": "application/json"}

        payload = {
            "name": self.comment_owner_id
            }
    
        try:
            response = requests.put(
                url, 
                json=payload,
                headers=headers, 
                cert=(cert_path, key_path),
                verify=False,
            )
        except Exception as e:
            logger.error(f"Failed to assign {ticket_id} - Error: {e}")
            logger.info(f"Response text: {response.text}")
        else:
            status = str(response.status_code)
            if status.startswith("2"):
                logger.info(f"{ticket_id} assigned to {self.comment_owner} succesfully")
            else:
                logger.error(f"Failed to assign {ticket_id} Error - {response.text}")
                logger.info(f"Response text: {response.text}")

    def close_resolved_tickets(self):
        self.current_time = datetime.now()
        for ticket in self.tickets:
            if (
                ticket.requires_approval is True
                and ticket.changes_approved is True
                and ticket.ticket_resolved is True
            ):
                url = self.jira_ticket_api + f"{ticket.ticket_id}/transitions"

                if ticket.ticket_id.lower().startswith("rcsor"):
                    transitions = ["5"]
                elif ticket.ticket_id.lower().startswith("entesc"):
                    # ticket_resolved = "141"
                    transitions = [""]

                else:
                    print(f"Unknown queue for ticket: {ticket.ticket_id}")
                    logger.info(f"Unknown queue for ticket: {ticket.ticket_id}")

                headers = {"Content-Type": "application/json"}

                print(f"Closing {ticket.ticket_id}")
                logger.info(f"Closing {ticket.ticket_id}")
                try:
                    for transition in transitions:
                        payload = {
                            "transition": {"id": transition}
                        }
                        response = requests.post(
                            url,
                            json=payload,
                            headers=headers,
                            cert=(cert_path, key_path),
                            verify=False,
                        )
                except Exception as e:
                    self.unapproved_tickets.append(ticket.ticket_id)
                    logger.error(f"Failed to close {ticket.ticket_id} - Error: {e}")
                    logger.info(f"Response text: {response.text}")
                    print(f"\nFailed to close {ticket.ticket_id} - Error: {e}\n")

                self.approved_tickets.append(ticket.ticket_id)
                ticket.time_to_resolution = (self.current_time - ticket.creation_time.replace(tzinfo=None))
                logger.info(f"{ticket.ticket_id} closed succesfully")
                print(f"{ticket.ticket_id} closed succesfully")
                self.update_assignee(ticket.ticket_id)
            else:
                self.unapproved_tickets.append(ticket.ticket_id)
                logger.info(f"{ticket.ticket_id} not approved.")

    def generate_approval_summary(self):
        start = f"Hi {self.analyst_handle},\n\n*Closed Tickets:*\n"
        middle = "\n\n*Remaining Tickets:*\n"
        approved = ""
        unapproved = ""

        for ticket_id in self.approved_tickets:
            approved += f"{ticket_id}\n"

        for ticket_id in self.unapproved_tickets:
            unapproved += f"{ticket_id}\n"

        if self.approved_tickets or self.unapproved_tickets:
            self.summary_comment = start + approved + middle + unapproved
            self.send_comment = True
        else:
            self.send_comment = False

    def update_summary(self):
        if self.send_comment is True:
            logger.info(f"Adding comment to {self.summary_ticket}")
            url = self.jira_ticket_api + self.summary_ticket

            headers = {"Accept": "application/json", "Content-Type": "application/json"}
            payload = {"update": {"comment": [{"add": {"body": self.summary_comment}}]}}

            response = requests.request(
                "PUT",
                url,
                json=payload,
                headers=headers,
                cert=(cert_path, key_path),
                verify=False,
            )

            status = str(response.status_code)
            if status.startswith("2"):
                self.summary_updated = True
                logger.info("Summary comment added")
                print("Summary comment added")
            else:
                self.summary_updated = False
                logger.info(f"Summary comment not added - Status: {status}")
                print(f"Summary comment not added - Status: {status}")
        else:
            logger.info(f"No comment for {self.summary_ticket}")
            self.summary_updated = False

    def add_summary_comment(self, comment):
        if self.send_comment is True:
            self.comment_sent = True
            logger.info(f"Adding comment to {self.summary_ticket}")
            url = self.jira_ticket_api + self.summary_ticket

            headers = {"Accept": "application/json", "Content-Type": "application/json"}
            payload = {"update": {"comment": [{"add": {"body": comment}}]}}

            response = requests.request(
                "PUT",
                url,
                json=payload,
                headers=headers,
                cert=(cert_path, key_path),
                verify=False,
            )

            status = str(response.status_code)
            if status.startswith("2"):
                logger.info("Comment added")
                print("Summary comment added")
            else:
                logger.info(f"Comment not added - Status: {status}")
                print(f"Summary comment not added - Status: {status}")
        else:
            logger.info(f"No comment for {self.summary_ticket}")

    def to_dict(self):
        tickets_dict = [ticket.to_dict() for ticket in self.tickets]

        approvals_dict = self.__dict__.copy()
        approvals_dict.pop("cert_path")
        approvals_dict.pop("key_path")
        approvals_dict.pop("tickets")
        approvals_dict["tickets"] = tickets_dict

        return approvals_dict

    def save_approvals(self):
        self.approvals_file = (
            self.approvals_prefix + "_" + str(int(time.time())) + ".json"
        )

        with open(self.approvals_file, "w") as file:
            approvals_dict = self.to_dict()
            json.dumps(approvals_dict, file, indent=4)

    def update_processed_tickets(self):
        with open(self.processed_tickets_file, "r") as file:
            try:
                processed_tickets_dict = json.load(file)
                if not processed_tickets_dict:
                    processed_tickets_dict = []
            except json.JSONDecodeError:
                logger.error(f"Error loading {self.processed_tickets_file}")
                processed_tickets_dict = []

        with open(self.processed_tickets_file, "w") as file:
            for ticket in self.tickets:
                ticket_dict = ticket.to_dict()
                ticket_dict.pop("whitelist_additions", None)  
                ticket_dict.pop("blacklist_additions", None)  
                ticket_dict.pop("blacklist_removals", None)  
                ticket_dict.pop("possible_changes", None)  
                ticket_dict.pop("comment_greeting", None)  
                ticket_dict.pop("comment_sign_off", None)  
                for indicator in ticket_dict.get("indicators", []):
                    indicator.pop("vt_link", None)  
                    indicator.pop("comment", None)  


                processed_tickets_dict.append(ticket_dict)

            json.dump(processed_tickets_dict, file, indent=4)

    def get_processed_tickets(self):
        for ticket in self.tickets:
            ApprovalFinder.processed_tickets.append(ticket.ticket_id)

    def update_tickets_in_progress(self):
        with open(self.tickets_in_progress_file, "r") as file:
            try:
                tickets_in_progress = json.load(file) or []
            except json.JSONDecodeError:
                logger.error(f"Error loading {self.tickets_in_progress_file}")
                tickets_in_progress = []

        tickets_in_progress = [
            ticket
            for ticket in tickets_in_progress
            if ticket.get("ticket_id", "") not in ApprovalFinder.processed_tickets
        ]

        with open(self.tickets_in_progress_file, "w") as file:
            json.dump(tickets_in_progress, file, indent=4)


    # def get_attribution(self, entry):
    #         if .ticket.queue = "sps":

    def generate_data_string(self, indicator):
        logger.info(f"Creating intel data string for {indicator.fqdn}")
        date = datetime.today().strftime("%m/%d/%Y")
        reason = f"Internal|Carrier|SecOps|{indicator.ticket.ticket_id}"

        if indicator.reviewed_resolution == "Allow":
            data_string = [
                date,
                indicator.matched_ioc.replace(".", "[.]"),
                "False-Positive",
                indicator.intel_feed.replace("|", "\\|"),
                indicator.intel_source.replace("|", "\\|"),
                reason.replace("|", "\\|"),
                indicator.ticket.ticket_id
            ]
        else:
            data_string = [
                date,
                indicator.fqdn.replace(".", "[.]"),
                "False-Negative",
                indicator.sps_feed,
                "-",
                reason.replace("|", "\\|"),
                indicator.ticket.ticket_id
            ]
        
        ApprovalFinder.intel_data_strings.append(data_string)

    def generate_data_string_comment(self):
        strings = []
        
        for data_string in ApprovalFinder.intel_data_strings:
            new_string = "|" + "|".join(data_string) + "|"
            strings.append(new_string)
        
        self.data_string_comment = "Intel update successful\n" + "\n".join(strings)