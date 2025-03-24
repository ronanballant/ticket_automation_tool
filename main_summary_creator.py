import socket

from config import (etp_tickets_in_progress_file, logger,
                    open_sps_summary_tickets_file, open_etp_summary_tickets_file, 
                    secops_member, sps_tickets_in_progress_file, cert_path, key_path, ssh_key_path)
from key_handler import KeyHandler
from summary_creator import SummaryCreator
from ticket import Ticket
from ticket_responder import TicketResponder

if __name__ == "__main__":
    logger.info("Summary process in progress")
    server_name = socket.gethostname()
    if "muc" in server_name:
        queue = "SPS"
        tickets_in_progress_file = sps_tickets_in_progress_file
        open_summary_tickets_file = open_sps_summary_tickets_file
    elif server_name == "oth-mpbv4":
        # queue = "SPS"
        # tickets_in_progress_file = sps_tickets_in_progress_file
        # open_summary_tickets_file = open_sps_summary_tickets_file
        queue = "ETP"
        tickets_in_progress_file = etp_tickets_in_progress_file
        open_summary_tickets_file = open_etp_summary_tickets_file
    elif "t4tools" in server_name:
        queue = "ETP"
        tickets_in_progress_file = etp_tickets_in_progress_file
        open_summary_tickets_file = open_etp_summary_tickets_file

    summary_creator = SummaryCreator(
        tickets_in_progress_file, open_summary_tickets_file
    )
    logger.info(f"Loading ticket data from {tickets_in_progress_file}")
    summary_creator.load_ticket_data()
    logger.info(f"Creating ticket instances")
    summary_creator.create_tickets()

    responder = TicketResponder(secops_member)
    logger.info(f"Finding unprocessed tickets")
    new_tickets = [
        ticket for ticket in Ticket.all_tickets if not ticket.linked_summary_ticket
    ]

    if not new_tickets:
        logger.info(f"No new tickets, exiting script")
        exit()

    key_handler = KeyHandler(cert_path, key_path, ssh_key_path)
    key_handler.get_key_names()
    key_handler.get_personal_keys()

    if queue == "SPS":
        try:
            logger.info(f"Creating SPS summary ticket")
            responder.create_sps_ticket(new_tickets)
        except Exception as e:
            print(f"\nFailed to create SPS summary ticket: {e}")
            logger.error(f"Failed to create SPS summary results ticket: {e}")
    elif queue == "ETP":
        try:
            logger.info(f"Creating ETP summary ticket")
            responder.create_etp_ticket(new_tickets)
        except Exception as e:
            print(f"\nFailed to create ETP summary ticket: {e}")
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
            print(f"\nFailed to add result comments to {responder.summary_ticket}: {e}")

        if responder.comment_succesfully_added is False:
            logger.info(f"Failed to add comment to {responder.summary_ticket}")
            summary_creator.archive_tickets()
            logger.info(f"Archived tickets to {summary_creator.archive_filename}")
            exit()

        logger.info(f"Linking summary ticket")
        Ticket.link_summary_ticket(responder.summary_ticket)
        logger.info(f"Saving updated tickets to {tickets_in_progress_file}")
        Ticket.save_current_tickets(tickets_in_progress_file)
        logger.info(
            f"Saving summary ticket to {summary_creator.open_summary_tickets_file}"
        )
        summary_creator.save_open_summary_ticket(responder.summary_ticket)
    
    key_handler.remove_personal_keys()
