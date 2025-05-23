import json
import os
import socket
import time
from datetime import datetime

from approval_finder import ApprovalFinder
from config import (blacklist_file, destination_region, directory_prefix,
                    etp_intel_repo, etp_processed_tickets_file,
                    etp_tickets_in_progress_file, get_logger,
                    intel_processor_path, jira_search_api, jira_ticket_api,
                    open_etp_summary_tickets_file,
                    open_sps_summary_tickets_file, project_folder,
                    search_fqdns_local_file, secops_feed_file,
                    secops_s3_aws_access_key, secops_s3_aws_secret_key,
                    secops_s3_bucket, secops_s3_endpoint,
                    sps_intel_update_file, sps_intel_update_s3_path,
                    sps_processed_tickets_file, sps_tickets_in_progress_file,
                    update_responses_s3_path, whitelist_file)
from git_repo_manager import GitRepoManager
from intel_entry import IntelEntry
from intel_processor import IntelProcessor
from key_handler import KeyHandler
from s3_client import S3Client
from ticket import Ticket

logger = get_logger("logs_intel_updater.txt")
cert_path = os.path.join(project_folder, ".intel_updater_personal_crt.crt")
key_path = os.path.join(project_folder, ".intel_updater_personal_key.key")
ssh_key_path = os.path.join(project_folder, ".intel_updater_ssh_key")


def close_summary(logger, approval_finder, summary_ticket):
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
    logger.info("Intel update process in progress")
    server_name = socket.gethostname()
    if "muc" in server_name:
        queue = "SPS"
        tickets_in_progress_file = sps_tickets_in_progress_file
        processed_tickets_file = sps_processed_tickets_file
        open_summary_tickets_file = open_sps_summary_tickets_file
    elif server_name == "oth-mpbv4":
        # queue = "SPS"
        # tickets_in_progress_file = sps_tickets_in_progress_file
        # processed_tickets_file = sps_processed_tickets_file
        # open_summary_tickets_file = open_sps_summary_tickets_file
        queue = "ETP"
        tickets_in_progress_file = etp_tickets_in_progress_file
        processed_tickets_file = etp_processed_tickets_file
        open_summary_tickets_file = open_etp_summary_tickets_file

    elif server_name == "prod-galaxy-t4tools.dfw02.corp.akamai.com":
        queue = "ETP"
        tickets_in_progress_file = etp_tickets_in_progress_file
        processed_tickets_file = etp_processed_tickets_file
        open_summary_tickets_file = open_etp_summary_tickets_file

    logger.info(f"tickets_in_progress_file path = {tickets_in_progress_file}")
    logger.info(f"open_summary_tickets_file path = {open_summary_tickets_file}")

    approval_finder = ApprovalFinder(
        logger,
        tickets_in_progress_file,
        open_summary_tickets_file,
        processed_tickets_file,
        jira_search_api,
        jira_ticket_api,
        cert_path,
        key_path
    )

    logger.info(f"Getting open summary tickets")
    approval_finder.get_open_summary_tickets()

    if not approval_finder.open_summary_tickets:
        logger.info(f"No open summary tickets. Exiting Script")
        exit()

    logger.info(f"Opening current tickets")
    approval_finder.open_current_tickets()
    approval_finder.create_tickets()

    if not Ticket.all_tickets:
        logger.info(f"No open tickets. Exiting Script")
        exit()

    key_handler = KeyHandler(logger, cert_path, key_path, ssh_key_path)
    key_handler.get_key_names()
    key_handler.get_personal_keys()

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
            logger.info(f"Getting approval status")
            approval_finder.find_if_approved()
            if approval_finder.intel_changes_approved is False:
                logger.info(f"Finding summary resolution status")
                approval_finder.find_if_resolved()
                if approval_finder.process_summary_ticket is False:
                    logger.info(f"Summary ticket closed...")
                    close_summary(logger, approval_finder, summary_ticket)
                    continue
                else:
                    logger.info(f"Threats not approved. Ending {summary_ticket} process...")
                    continue
            else:
                logger.info(f"Changes approved")

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
            intel_processor = IntelProcessor(logger, IntelEntry.all_intel_entries)
            intel_processor.process_indicators()

            if queue == "SPS":
                if intel_processor.intel_entries:
                    intel_processor.add_to_sps_intel_file()

                    if "muc" in server_name:
                        logger.info(f"Running on {server_name}. Starting S3 process")
                        s3_client = S3Client(
                            logger,
                            destination_region,
                            secops_s3_endpoint,
                            secops_s3_bucket,
                            secops_s3_aws_access_key,
                            secops_s3_aws_secret_key,
                            directory_prefix,
                        )
                        s3_client.initialise_client()
                        intel_processor.update_triggered = True
                        if intel_processor.whitelist or intel_processor.blacklist:
                            try:
                                s3_client.write_file(
                                    sps_intel_update_file, sps_intel_update_s3_path
                                )
                            except Exception as e:
                                logger.error(
                                    f"Failed to send {sps_intel_update_file} to {sps_intel_update_s3_path}:\n{e}"
                                )
                                intel_processor.update_triggered = False
                                intel_processor.error_comment = (
                                    f"Failed to write intel update to S3 bucket:\n{e}"
                                )
                            else:
                                recheck = True
                                max_retries = 5
                                retry_count = 0
                                update_results = '"success": false'
                                while recheck and retry_count < max_retries:
                                    time.sleep(60)
                                    s3_client.read_s3_file(update_responses_s3_path)

                                    if s3_client.file_content:
                                        try:
                                            json_results = json.loads(
                                                s3_client.file_content.strip()
                                            )
                                            if json_results:
                                                update_results = json_results
                                                recheck = False
                                            else:
                                                retry_count += 1
                                        except json.JSONDecodeError as e:
                                            retry_count += 1
                                            logger.info("Attempt %s", retry_count)
                                    else:
                                        retry_count += 1
                                        logger.info("Attempt %s", retry_count)

                                if '"success": false' in update_results:
                                    intel_processor.update_triggered = False
                                    intel_processor.error_comment = (
                                        "*{color:#de350b}!!! Failed to trigger intel update !!!{color}*"
                                        + "{code:java} \n"
                                        + update_results
                                        + "{code}"
                                    )

                                s3_client.write_file(
                                    search_fqdns_local_file, update_responses_s3_path
                                )
                        else:
                            logger.info(f"No Whitelist or Blacklist entries to process")
                    else:
                        logger.info(f"Transfering {sps_intel_update_file} to SPOF VM")
                        intel_processor.transfer_sps_update_file()
                        logger.info(f"Triggering {intel_processor_path} on SPOF VM")
                        intel_processor.trigger_sps_intel_update()

                    approval_finder.generate_data_string_comment()
                    if intel_processor.update_triggered is True:
                        approval_finder.add_summary_comment(
                            approval_finder.data_string_comment
                        )
                    else:
                        approval_finder.add_summary_comment(intel_processor.error_comment)
                else:
                    intel_processor.update_triggered = True
            elif queue == "ETP":
                if intel_processor.intel_entries:
                    intel_processor.update_triggered = True
                    error_comment = None  

                    try:
                        intel_processor.update_triggered = True
                        logger.info("Loading SSH Keys")
                        key_handler.get_ssh_key()

                        git_manager = GitRepoManager(logger, etp_intel_repo)
                        logger.info("Starting SSH Agent")
                        git_manager.start_ssh_agent()
                        logger.info("Adding SSH Keys")
                        git_manager.add_ssh_key(ssh_key_path)
                        logger.info("Checkout master...")
                        git_manager.checkout_master()
                        logger.info("Pulling repo...")
                        git_manager.git_pull()
                        branch_name = (
                            f'customer_escalations/{datetime.today().strftime("%Y-%m-%d-%H%M")}'
                        )
                        logger.info(f"Branch name: {branch_name}")
                        git_manager.create_new_branch(branch_name)

                        intel_processor.add_to_etp_whitelist()
                        intel_processor.add_to_etp_blacklist()
                        intel_processor.remove_from_etp_manual_blacklist()
                        intel_processor.update_triggered = True

                        if intel_processor.add_error_comment is True:
                            approval_finder.add_summary_comment(intel_processor.error_comment)
                        else:
                            git_manager.git_add(
                                [whitelist_file, blacklist_file, secops_feed_file]
                            )
                            git_manager.git_commit("Ticket Automation")
                            git_manager.git_status()
                            git_manager.push_changes(branch_name)
                            git_manager.get_pr_link()
                            approval_finder.add_summary_comment(git_manager.pr_comment)
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
