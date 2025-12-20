import argparse
import os

from config import (
    DATA_DIR,
    ETP_TICKETS_IN_PROGRESS_FILE,
    get_logger,
    OPEN_ETP_SUMMARY_TICKETS_FILE,
    OPEN_SPS_SUMMARY_TICKETS_FILE,
    SECOPS_MEMBER,
    SUMMARY_CERT_PATH,
    SUMMARY_KEY_PATH,
    SUMMARY_SSH_KEY_PATH,
    SPS_TICKETS_IN_PROGRESS_FILE,
)
from key_handler import KeyHandler
from summary_creator import SummaryCreator
from ticket import Ticket
from ticket_responder import TicketResponder

logger = get_logger(str(DATA_DIR / "summary_creator.log"))


def parse_args():
    parser = argparse.ArgumentParser(description="Ticket Automation Tool")
    parser.add_argument(
        "-q",
        "--queue",
        default="etp",
        type=str,
        help="Enter sps or etp to choose a queue",
    )
    parser.add_argument(
        "-t",
        "--tickets",
        # default="RCSOR-8167",
        required=False,
        help="A comma seperated string of specific tickets to analyse",
    )
    parser.add_argument(
        "-a",
        "--archive_path",
        required=False,
        help="A path to the archived tickets you wish to resummarise (-r also required).",
    )
    parser.add_argument(
        "-r",
        "--resummarise",
        action="store_true",
        help="Use -r if you wish to resummarise archived tickets (-a also required).",
    )
    args = parser.parse_args()

    if args.queue is None:
        """If no queue is selected"""
        parser.print_help()
        exit(1)
    else:
        return args


def re_summaraise(archived_file):
    pass


if __name__ == "__main__":
    args = parse_args()

    queue = args.queue.lower()
    if args.queue.lower() not in ["sps", "etp"]:
        print("Please enter sps or etp to choose a queue!")
        logger.error(f"{args.queue} is an invalid entry")
        exit(1)

    logger.info("Summary process in progress")
    if queue.lower() == "sps":
        queue = "SPS"
        tickets_in_progress_file = SPS_TICKETS_IN_PROGRESS_FILE
        open_summary_tickets_file = OPEN_SPS_SUMMARY_TICKETS_FILE
    elif queue.lower() == "etp":
        queue = "ETP"
        tickets_in_progress_file = ETP_TICKETS_IN_PROGRESS_FILE
        open_summary_tickets_file = OPEN_ETP_SUMMARY_TICKETS_FILE

    if args.resummarise is True:
        if args.archive_path:
            tickets_in_progress_file = args.archive_path
        else:
            logger.error("No archive file provided in -a. exiting...")
            exit()

    summary_creator = SummaryCreator(
        logger, tickets_in_progress_file, open_summary_tickets_file
    )
    logger.info(f"Loading ticket data from {tickets_in_progress_file}")
    summary_creator.load_ticket_data()
    logger.info("Creating ticket instances")
    summary_creator.create_tickets()

    responder = TicketResponder(logger, SECOPS_MEMBER, SUMMARY_CERT_PATH, SUMMARY_KEY_PATH)
    logger.info("Finding unprocessed tickets")
    new_tickets = [
        ticket for ticket in Ticket.all_tickets if not ticket.linked_summary_ticket
    ]

    if not new_tickets:
        logger.info("No new tickets, exiting script")
        exit()

    key_handler = KeyHandler(logger, SUMMARY_CERT_PATH, SUMMARY_KEY_PATH, SUMMARY_SSH_KEY_PATH)
    key_handler.get_key_names()
    key_handler.get_personal_keys()

    if queue == "SPS":
        try:
            logger.info("Creating SPS summary ticket")
            responder.create_sps_ticket(new_tickets)
        except Exception as e:
            logger.error(f"Failed to create SPS summary results ticket: {e}")
    elif queue == "ETP":
        try:
            logger.info("Creating ETP summary ticket")
            responder.create_etp_ticket(new_tickets)
        except Exception as e:
            logger.error(f"Failed to create ETP summary results ticket: {e}")

    if responder.summary_ticket_created is True:
        try:
            logger.info(f"Adding comment to {responder.summary_ticket}")
            responder.add_comment()
        except Exception as e:
            responder.comment_succesfully_added = False
            logger.info(
                f"Failed to add result comments to {responder.summary_ticket}: {e}"
            )

        if responder.comment_succesfully_added is False:
            logger.info(f"Failed to add comment to {responder.summary_ticket}")
            summary_creator.archive_tickets()
            logger.info(f"Archived tickets to {summary_creator.archive_filename}")
            exit()

        logger.info("Linking summary ticket")
        Ticket.link_summary_ticket(responder.summary_ticket)
        logger.info(f"Saving updated tickets to {tickets_in_progress_file}")
        Ticket.save_current_tickets(tickets_in_progress_file)
        logger.info(
            f"Saving summary ticket to {summary_creator.open_summary_tickets_file}"
        )
        summary_creator.save_open_summary_ticket(responder.summary_ticket)

    logger.info("Removing personal keys")
    key_handler.remove_personal_keys()
