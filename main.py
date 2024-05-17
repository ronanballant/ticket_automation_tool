#!/usr/bin/python3

import argparse
import datetime
import time

from automation_logger import AutomationLogger
from config import logger
from entity import Entity
from etp_intel_fetcher import EtpIntelFetcher
from intel_processor import IntelProcessor
from jira_ticket_resolver import TicketResolver
from response_creator import ResponseCreator
from rule_fetcher import RuleFetcher
from sps_intel_fetcher import SpsIntelFetcher
from ticket_fetcher import TicketFetcher
from ticket_responder import TicketResponder
from virus_total_fetcher import VirusTotalFetcher


def parse_args():
    parser = argparse.ArgumentParser(description="Ticket Automation Tool")
    parser.add_argument(
        "-q",
        "--queue",
        # default='sps',
        type=str,
        help="Enter sps or etp to choose a queue",
    )
    args = parser.parse_args()

    if args.queue is None:
        """If no queue is selected"""
        parser.print_help()
        exit(1)
    else:
        return args


def run_sps_process():
    start_time = time.time()
    print("SPS Ticket Automation In Progress...")
    logger.info("SPS Process In Progress...")

    print("Processing Tickets")
    tickets = TicketFetcher("sps").tickets
    for ticket, values in tickets.items():
        ticket_id = ticket
        domains = values.get("domains")
        urls = values.get("urls")
        ticket_type = values.get("ticket_type")
        reporter = values.get("reporter")
        entity_type = values.get("entity_type")
        is_guardicore_ticket = False

        if ticket_type == "FN" or ticket_type == "FP":
            logger.info("Creating Entity Instances")
            for domain in domains:
                Entity(
                    "SPS", domain, entity_type, urls, ticket_id, ticket_type, reporter, is_guardicore_ticket
                )

    print("Querying SPS intel")
    logger.info("Querying SPS intel")
    SpsIntelFetcher(Entity.entity_list)

    print("Loading Rule-Set")
    logger.info("Loading Rule-Set")
    rule_set = RuleFetcher()
    file_time = time.time()
    for entity in Entity.entity_list:
        print(f"Processing {entity.entity}")
        VirusTotalFetcher(entity)
        TicketResolver(entity, rule_set.rules, file_time)
        ResponseCreator(entity)

    responder = TicketResponder(Entity.entity_list)
    print("\nCreating SPS Results Ticket")
    # responder.create_sps_ticket()
    print("\nResponding to Tickets")
    responder.update_tickets()

    end_time = time.time()
    runtime = datetime.timedelta(seconds=end_time - start_time)
    automation_logger = AutomationLogger(
        Entity.entity_list, responder, start_time, runtime
    )
    automation_logger.write_sps_data()

    # IntelProcessor(Entity.entity_list)
    print("Process Finished...")
    logger.info("SPS ticket automation Finished")

def run_etp_process():
    start_time = time.time()
    print("ETP Process In Progress...")
    logger.info("ETP Process In Progress...")

    print("Processing Tickets")
    tickets = TicketFetcher("etp").tickets
    for ticket, values in tickets.items():
        ips = values.get("ips")
        ticket_id = ticket
        domains = values.get("domains")
        urls = values.get("urls")
        ticket_type = values.get("ticket_type")
        reporter = values.get("reporter")
        entity_type = values.get("entity_type")
        is_guardicore_ticket = values.get("is_guardicore_ticket")

        if ticket_type == "FN" or ticket_type == "FP":
            logger.info("Creating Entity Instances")
            for domain in domains:
                Entity(
                    "ETP", domain, entity_type, urls, ticket_id, ticket_type, reporter, is_guardicore_ticket, ips
                )

    print("Querying ETP intel")
    logger.info("Querying ETP intel")
    EtpIntelFetcher(Entity.entity_list)

    file_time = time.time()
    print("Loading Rule-Set")
    logger.info("Loading Rule-Set")
    rule_set = RuleFetcher()
    for entity in Entity.entity_list:
        print(f"Processing {entity.entity}")
        VirusTotalFetcher(entity)
        TicketResolver(entity, rule_set.rules, file_time)
        ResponseCreator(entity)

    responder = TicketResponder(Entity.entity_list)
    print("\nCreating ETP Results Ticket")
    responder.create_etp_ticket()
    print("\nResponding to Tickets")
    responder.update_tickets()
    
    end_time = time.time()
    runtime = datetime.timedelta(seconds=end_time - start_time)
    automation_logger = AutomationLogger(
        Entity.entity_list, responder, start_time, runtime
    )
    automation_logger.write_etp_data()
    # IntelProcessor(Entity.entity_list)
    print("ETP ticket automation Finished")
    logger.info("ETP ticket automation Finished")


if __name__ == "__main__":
    args = parse_args()

    if args.queue.lower() not in ["sps", "etp"]:
        print("Please enter sps or etp to choose a queue!")
        exit(1)

    try:
        if args.queue.lower() == "sps":
            run_sps_process()
        else:
            run_etp_process()
    except Exception as e:
        print(f"Process Failed!... \nError: {e}")
        logger.error(f"Process Failed!... Error: {e}")
