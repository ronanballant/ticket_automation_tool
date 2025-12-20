import argparse

import os
from datetime import datetime

from approval_finder import ApprovalFinder
from config import (
    BLACKLIST_FILE,
    ETP_INTEL_REPO,
    ETP_PROCESSED_TICKETS_FILE,
    ETP_TICKETS_IN_PROGRESS_FILE,
    get_logger,
    JIRA_SEARCH_API,
    JIRA_TICKET_API,
    OPEN_ETP_SUMMARY_TICKETS_FILE,
    OPEN_SPS_SUMMARY_TICKETS_FILE,
    PROJECT_DIR,
    SECOPS_FEED_FILE,
    SPS_PROCESSED_TICKETS_FILE,
    SPS_TICKETS_IN_PROGRESS_FILE,
    WHITELIST_FILE,
)
from git_repo_manager import GitRepoManager
from intel_entry import IntelEntry
from intel_processor import IntelProcessor
from key_handler import KeyHandler
from ticket import Ticket

logger = get_logger("logs_intel_updater.txt")
cert_path = os.path.join(PROJECT_DIR, ".intel_updater_personal_crt.crt")
key_path = os.path.join(PROJECT_DIR, ".intel_updater_personal_key.key")
ssh_key_path = os.path.join(PROJECT_DIR, ".intel_updater_ssh_key")


def parse_args():
    parser = argparse.ArgumentParser(description="Ticket Automation - Intel Updater")
    parser.add_argument(
        "-q",
        "--queue",
        default="etp",
        type=str,
        help="Enter sps or etp to choose a queue",
    )
    parser.add_argument(
        "-s",
        "--summary_ticket",
        # default="RCSOR-8173",
        required=False,
        help="A comma seperated string of specific tickets to analyse",
    )
    args = parser.parse_args()

    if args.queue is None or args.queue.lower() not in ["etp", "sps"]:
        """If no queue is selected"""
        parser.print_help()
        exit(1)
    else:
        return args


def close_summary(logger, approval_finder, summary_ticket):
    logger.info(f"Removing {summary_ticket} from {open_summary_tickets_file}")
    approval_finder.clear_processed_summary_ticket()

    logger.info(f"Saving processed tickets to {approval_finder.processed_tickets_file}")
    approval_finder.update_processed_tickets()
    logger.info("Generating processed tickets list")
    approval_finder.get_processed_tickets()
    logger.info(
        f"Removing resolved tickets from {summary_ticket} from {open_summary_tickets_file}"
    )
    approval_finder.update_tickets_in_progress()


if __name__ == "__main__":
    logger.info("Intel update process in progress")

    args = parse_args()

    if args.queue.lower() == "sps":
        queue = "SPS"
        tickets_in_progress_file = SPS_TICKETS_IN_PROGRESS_FILE
        processed_tickets_file = SPS_PROCESSED_TICKETS_FILE
        open_summary_tickets_file = OPEN_SPS_SUMMARY_TICKETS_FILE
    else:
        queue = "ETP"
        tickets_in_progress_file = ETP_TICKETS_IN_PROGRESS_FILE
        processed_tickets_file = ETP_PROCESSED_TICKETS_FILE
        open_summary_tickets_file = OPEN_ETP_SUMMARY_TICKETS_FILE

    logger.info(f"Processing {queue} queue...")
    logger.info(f"tickets_in_progress_file path = {tickets_in_progress_file}")
    logger.info(f"open_summary_tickets_file path = {open_summary_tickets_file}")

    approval_finder = ApprovalFinder(
        logger,
        tickets_in_progress_file,
        open_summary_tickets_file,
        processed_tickets_file,
        JIRA_SEARCH_API,
        JIRA_TICKET_API,
        cert_path,
        key_path,
    )

    logger.info("Getting open summary tickets")
    approval_finder.get_open_summary_tickets()

    if not approval_finder.open_summary_tickets:
        logger.info("No open summary tickets. Exiting Script")
        exit()

    logger.info("Opening current tickets")
    approval_finder.open_current_tickets()
    approval_finder.create_tickets()

    if not Ticket.all_tickets:
        logger.info("No open tickets. Exiting Script")
        exit()

    key_handler = KeyHandler(logger, cert_path, key_path, ssh_key_path)
    key_handler.get_key_names()
    key_handler.get_personal_keys()
    key_handler.get_feed_processor_api_key()
    feed_processor_api_key = key_handler.feed_processor_api_key

    approval_finder.group_tickets()
    for summary_ticket in approval_finder.open_summary_tickets:
        try:
            logger.info(f"Processing {summary_ticket}")
            approval_finder.summary_ticket = summary_ticket
            approval_finder.tickets = approval_finder.grouped_tickets.get(
                summary_ticket, {}
            )

            logger.info(f"Fetching {summary_ticket}")
            approval_finder.open_jira_ticket()
            logger.info(f"Parsing {summary_ticket} description")
            approval_finder.parse_ticket()
            logger.info(f"Fetching {summary_ticket} comments")
            approval_finder.get_comments()
            logger.info("Getting approval status")
            approval_finder.find_if_approved()
            if approval_finder.intel_changes_approved is False:
                logger.info("Finding summary resolution status")
                approval_finder.find_if_resolved()
                if approval_finder.process_summary_ticket is False:
                    logger.info("Summary ticket closed...")
                    close_summary(logger, approval_finder, summary_ticket)
                    continue
                else:
                    logger.info(
                        f"Threats not approved. Ending {summary_ticket} process..."
                    )
                    continue
            else:
                logger.info("Changes approved")

            logger.info("Parsing approved intel updates")
            approval_finder.parse_reviewed_changes()
            logger.info("Finding resolved tickets")
            approval_finder.find_approved_intel_changes()
            logger.info("Closing resolved tickets")
            approval_finder.close_resolved_tickets()
            logger.info("Summarising closed tickets")
            approval_finder.generate_approval_summary()
            logger.info(f"Sending summary comment to {summary_ticket}")
            approval_finder.update_summary()

            logger.info("Processing Intel changes")
            intel_processor = IntelProcessor(logger, IntelEntry.all_intel_entries, feed_processor_api_key)

            intel_processor.update_triggered = True
            if queue == "SPS":
                if intel_processor.intel_entries:
                    intel_processor.process_sps_indicators()
                    error_comment = False
                    summary_comment = False
                    for intel_entry in IntelEntry.all_intel_entries:
                        for whitelisted_entry in intel_entry.whitelist:
                            if (
                                whitelisted_entry.update_approved
                                and whitelisted_entry.update_approved is True
                            ):
                                entry = whitelisted_entry.approved_intel_change.strip().split(",")
                                fqdn = entry[0]
                                ticket = entry[1]
                                intel_processor.linode_whitelist_addition(fqdn, ticket)
                                whitelisted_entry.update_status_code = (
                                    intel_processor.linode_update_status_code
                                )
                                whitelisted_entry.linode_update_response = (
                                    intel_processor.linode_update_response
                                )

                                if (
                                    '"success": false'
                                    in whitelisted_entry.linode_update_response
                                    or whitelisted_entry.update_status_code[0] != "2"
                                ):
                                    whitelisted_entry.update_triggered = False
                                    error_comment = True
                                    intel_processor.error_comment.append(
                                        f"{fqdn} - Status Code: {whitelisted_entry.update_status_code} - Response: {whitelisted_entry.linode_update_response}"
                                    )
                                else:
                                    summary_comment = True
                                    intel_processor.summary_comment.append(
                                        whitelisted_entry.indicator.intel_summary_string
                                    )
                                    whitelisted_entry.update_triggered = True

                        for whitelisted_removal_entry in intel_entry.whitelist_removal:
                            if (
                                whitelisted_removal_entry.update_approved
                                and whitelisted_removal_entry.update_approved is True
                            ):
                                entry = whitelisted_removal_entry.approved_intel_change.strip().split(",")
                                fqdn = entry[0]
                                ticket = entry[1]
                                intel_processor.linode_whitelist_removal(fqdn, ticket)
                                whitelisted_removal_entry.update_status_code = (
                                    intel_processor.linode_update_status_code
                                )
                                whitelisted_removal_entry.linode_update_response = (
                                    intel_processor.linode_update_response
                                )
                                if (
                                    '"success": false'
                                    in whitelisted_removal_entry.linode_update_response
                                    or whitelisted_removal_entry.update_status_code[0]
                                    != "2"
                                ):
                                    whitelisted_removal_entry.update_triggered = False
                                    error_comment = True
                                    intel_processor.error_comment.append(
                                        f"{fqdn} - Status Code: {whitelisted_removal_entry.update_status_code} - Response: {whitelisted_removal_entry.linode_update_response}"
                                    )
                                else:
                                    summary_comment = True
                                    intel_processor.summary_comment.append(
                                        whitelisted_removal_entry.indicator.intel_summary_string
                                    )
                                    whitelisted_removal_entry.update_triggered = True

                        for blocklist_entry in intel_entry.blacklist:
                            if (
                                blocklist_entry.update_approved
                                and blocklist_entry.update_approved is True
                            ):
                                entry = (
                                    blocklist_entry.approved_intel_change.strip().split(",")
                                )
                                fqdn = entry[0]
                                ticket = entry[1]
                                block_feed = entry[2]
                                intel_processor.linode_blocklist_update(
                                    fqdn, ticket, block_feed
                                )
                                blocklist_entry.update_status_code = (
                                    intel_processor.linode_update_status_code
                                )
                                blocklist_entry.linode_update_response = (
                                    intel_processor.linode_update_response
                                )
                                if (
                                    '"success": false'
                                    in blocklist_entry.linode_update_response
                                    or blocklist_entry.update_status_code[0] != "2"
                                ):
                                    error_comment = True
                                    blocklist_entry.update_triggered = False
                                    intel_processor.error_comment.append(
                                        f"{fqdn} - Status Code: {blocklist_entry.linode_update_response} - Response: {blocklist_entry.linode_update_response}"
                                    )
                                else:
                                    summary_comment = True
                                    intel_processor.summary_comment.append(
                                        blocklist_entry.indicator.intel_summary_string
                                    )
                                    blocklist_entry.update_triggered = True
                                    # intel_processor.summary_comment.append(.intel_summary_string)

                    # approval_finder.generate_data_string_comment()

                    if summary_comment is True or error_comment is True:
                        intel_processor.generate_data_string_comment()
                        approval_finder.add_summary_comment(
                            intel_processor.data_string_comment
                        )

                    if not summary_comment or error_comment is not True:
                        intel_processor.update_triggered = True
                        approval_finder.summary_updated
                else:
                    close_summary(logger, approval_finder, summary_ticket)
            elif queue == "ETP":
                intel_processor.process_indicators()
                if intel_processor.intel_entries:
                    intel_processor.update_triggered = True
                    error_comment = None

                    try:
                        intel_processor.update_triggered = True
                        logger.info("Loading SSH Keys")
                        key_handler.get_ssh_key()

                        git_manager = GitRepoManager(logger, ETP_INTEL_REPO)
                        logger.info("Starting SSH Agent")
                        git_manager.start_ssh_agent()
                        logger.info("Adding SSH Keys")
                        git_manager.add_ssh_key(ssh_key_path)
                        logger.info("Checkout master...")
                        git_manager.checkout_master()
                        logger.info("Pulling repo...")
                        git_manager.git_pull()
                        branch_name = f"customer_escalations/{datetime.today().strftime('%Y-%m-%d-%H%M%S')}"
                        logger.info(f"Branch name: {branch_name}")
                        git_manager.create_new_branch(branch_name)

                        intel_processor.add_to_etp_whitelist()
                        intel_processor.add_to_etp_blacklist()
                        intel_processor.remove_from_etp_manual_blacklist()
                        intel_processor.update_triggered = True

                        if intel_processor.add_error_comment is True:
                            approval_finder.add_summary_comment(
                                intel_processor.error_comment
                            )
                        else:
                            if (
                                intel_processor.whitelist
                                or intel_processor.blacklist
                                or intel_processor.manual_blacklist
                            ):
                                git_manager.git_add(
                                    [WHITELIST_FILE, BLACKLIST_FILE, SECOPS_FEED_FILE]
                                )
                                git_manager.git_commit("Ticket Automation")
                                git_manager.git_status()
                                git_manager.push_changes(branch_name)
                                git_manager.get_pr_link()
                                approval_finder.add_summary_comment(
                                    git_manager.pr_comment
                                )
                            else:
                                approval_finder.add_summary_comment(
                                    "No changes to push.."
                                )
                    except Exception as e:
                        logger.error(f"Intel update failed: {str(e)}", exc_info=True)
                        error_comment = (
                            "Intel Update Automation Failed.\n\n"
                            f"Error: {str(e)}\n"
                            "Please investigate manually."
                        )

                    finally:
                        git_manager.kill_ssh_agent()
                        key_handler.remove_ssh_keys()

                        if error_comment:
                            approval_finder.add_summary_comment(error_comment)

                else:
                    intel_processor.update_triggered = True

            if (
                intel_processor.update_triggered is True
                and approval_finder.summary_updated is True
            ):
                close_summary(logger, approval_finder, summary_ticket)
        except Exception as e:
            logger.error(f"Intel update failed: {str(e)}", exc_info=True)
            error_comment = (
                "Intel Update Automation Failed.\n\n"
                f"Error: {str(e)}\n"
                "Please investigate manually."
            )
            approval_finder.add_summary_comment(error_comment)

    key_handler.remove_personal_keys()
