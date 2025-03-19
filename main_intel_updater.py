import socket
from datetime import datetime

from approval_finder import ApprovalFinder
from config import (cert_path, blacklist_file, etp_intel_repo,
                    etp_processed_tickets_file, etp_tickets_in_progress_file,
                    intel_processor_path, jira_search_api,
                    jira_ticket_api, key_path, logger,
                    open_etp_summary_tickets_file,
                    open_sps_summary_tickets_file, 
                    sps_intel_update_file, sps_processed_tickets_file,
                    sps_tickets_in_progress_file, ssh_key_path, whitelist_file)
from git_repo_manager import GitRepoManager
from intel_entry import IntelEntry
from intel_processor import IntelProcessor
from key_handler import KeyHandler
from ticket import Ticket


def close_summary(approval_finder, summary_ticket):
    logger.info(f"Removing {summary_ticket} from {open_summary_tickets_file}")
    approval_finder.clear_processed_summary_ticket()

    logger.info(f"Saving processed tickets to {approval_finder.processed_tickets_file}")
    approval_finder.update_processed_tickets()
    logger.info(f"Generating processed tickets list")
    approval_finder.get_processed_tickets()
    logger.info(
        f"Removing resolved tickets from {summary_ticket} from {open_summary_tickets_file}"
    )
    approval_finder.update_tickets_in_progress()


if __name__ == "__main__":
    server_name = socket.gethostname()
    if "muc" in server_name:
        queue = "SPS"
        tickets_in_progress_file = sps_tickets_in_progress_file
        processed_tickets_file = sps_processed_tickets_file
        open_summary_tickets_file = open_sps_summary_tickets_file
    elif server_name == "oth-mpbv4":
        queue = "SPS"
        tickets_in_progress_file = sps_tickets_in_progress_file
        processed_tickets_file = sps_processed_tickets_file
        open_summary_tickets_file = open_sps_summary_tickets_file
        # queue = "ETP"
        # tickets_in_progress_file = etp_tickets_in_progress_file
        # processed_tickets_file = etp_processed_tickets_file
        # open_summary_tickets_file = open_etp_summary_tickets_file

    elif server_name == "prod-galaxy-t4tools.dfw02.corp.akamai.com":
        queue = "ETP"
        tickets_in_progress_file = etp_tickets_in_progress_file
        processed_tickets_file = etp_processed_tickets_file
        open_summary_tickets_file = open_etp_summary_tickets_file

    logger.info(f"tickets_in_progress_file path = {tickets_in_progress_file}")
    logger.info(f"open_summary_tickets_file path = {open_summary_tickets_file}")

    approval_finder = ApprovalFinder(
        tickets_in_progress_file,
        open_summary_tickets_file,
        processed_tickets_file,
        jira_search_api,
        jira_ticket_api
    )

    logger.info(f"Getting open summary tickets")
    approval_finder.get_open_summary_tickets()

    if not approval_finder.open_summary_tickets:
        logger.info(f"No open summary tickets. Exiting Script")
        exit()

    logger.info(f"Getting open summary tickets")
    approval_finder.open_current_tickets()
    approval_finder.create_tickets()

    if not Ticket.all_tickets:
        logger.info(f"No open tickets. Exiting Script")
        exit()

    approval_finder.group_tickets()
    for summary_ticket in approval_finder.open_summary_tickets:
        logger.info(f"Processing {summary_ticket}")
        approval_finder.summary_ticket = summary_ticket
        approval_finder.tickets = approval_finder.grouped_tickets.get(
            summary_ticket, {}
        )

        logger.info(f"Fetching {summary_ticket} comments")
        approval_finder.get_comments()
        logger.info(f"Getting approval status")
        approval_finder.find_if_approved()

        if approval_finder.intel_changes_approved is False:
            logger.info(f"Changes not approved. Ending process...")
            continue

        logger.info(f"Changes approved - fetching {summary_ticket}")
        approval_finder.open_jira_ticket()
        logger.info(f"Parsing {summary_ticket} description")
        approval_finder.parse_ticket()
        logger.info(f"Finding summary resolution status")
        approval_finder.find_if_resolved()

        if approval_finder.process_summary_ticket is False:
            close_summary(approval_finder, summary_ticket)
            continue

        logger.info(f"Parsing approved intel updates")
        approval_finder.parse_reviewed_changes()
        logger.info(f"Finding resolved tickets")
        approval_finder.find_approved_intel_changes()
        logger.info(f"Closing resolved tickets")
        approval_finder.close_resolved_tickets()
        logger.info(f"Summarising closed tickets")
        approval_finder.generate_approval_summary()
        logger.info(f"Sending summary comment to {summary_ticket}")
        approval_finder.update_summary()

        logger.info(f"Processing Intel changes")
        intel_processor = IntelProcessor(IntelEntry.all_intel_entries)
        intel_processor.process_indicators()
        logger.info(f"Adding Intel changes to {sps_intel_update_file}")

        if queue == "SPS":
            if intel_processor.intel_entries:
                intel_processor.add_to_sps_intel_file()
                logger.info(f"Transfering {sps_intel_update_file} to SPOF VM")
                intel_processor.transfer_sps_update_file()
                logger.info(f"Triggering {intel_processor_path} on SPOF VM")
                intel_processor.trigger_sps_intel_update()
                approval_finder.generate_data_string_comment()
                approval_finder.add_summary_comment(approval_finder.data_string_comment)
            else:
                intel_processor.update_triggered = True
        elif queue == "ETP":
            if intel_processor.intel_entries:
                key_handler = KeyHandler(cert_path, key_path, ssh_key_path, approval_finder.comment_owner)
                key_handler.get_key_names()
                key_handler.get_ssh_key()
                key_handler.get_personal_keys()

                git_manager = GitRepoManager(etp_intel_repo)
                git_manager.add_ssh_key()
                git_manager.checkout_master()
                git_manager.git_pull()

                intel_processor.add_to_etp_whitelist()
                intel_processor.add_to_etp_blacklist()
                intel_processor.remove_from_etp_manual_blacklist()
                intel_processor.update_triggered = True

                if intel_processor.add_error_comment is True:
                    approval_finder.add_summary_comment(intel_processor.error_comment)
                else:
                    branch_name = f'customer_escalations/{datetime.today().strftime("%Y-%m-%d-%H00")}'
                    git_manager.create_new_branch(branch_name)
                    git_manager.git_add([whitelist_file, blacklist_file])
                    git_manager.git_commit("Ticket Automation")
                    git_manager.push_changes(branch_name, approval_finder.user_name)
                    git_manager.get_pr_link()
                    approval_finder.add_summary_comment(git_manager.pr_comment)
            else:
                intel_processor.update_triggered = True

        if (
            intel_processor.update_triggered is True
            and approval_finder.summary_updated is True
        ):
            close_summary(approval_finder, summary_ticket)
    
    key_handler.remove_keys()
