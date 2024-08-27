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
from initialise_mongo import InitialiseMongo

def parse_args():
    parser = argparse.ArgumentParser(description="Ticket Automation Tool")
    parser.add_argument(
        "-q",
        "--queue",
        default='sps',
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
    ticket_dict = {}
    start_time = time.time()
    print("\n\nSPS Ticket Automation In Progress...\n")
    logger.info("SPS Process In Progress...")

    try:
        rule_set = RuleFetcher()
    except Exception as e:
        print(f"\nFailed to load Rule-Set: {e}")
        logger.error(f"Failed to load Rule-Set: {e}")
        return

    print("\nFetching Tickets")
    try:
        tickets = TicketFetcher("sps").tickets
    except Exception as e:
        print(f"\nFailed to fetch tickets: {e}")
        logger.error(f"Failed to fetch tickets: {e}")
        return

    print("Parsing tickets")
    logger.info("Parsing tickets")
    try:
        for ticket, values in tickets.items():
            ips = values.get('ips')
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
                    try:
                        entity = Entity(
                            "SPS", domain, entity_type, urls, ticket_id, ticket_type, reporter, is_guardicore_ticket, ips
                        )
                    except Exception as e:
                        print(f"Failed to create entity for {domain}: {e}")
                        logger.error(f"Failed to create entity for {domain}: {e}")
                        
                    if entity.append_entity is True:
                        if entity.ticket_id in ticket_dict:
                            ticket_dict[entity.ticket_id].append(entity)
                        else:
                            ticket_dict[entity.ticket_id] = [entity]
    except Exception as e:
        print(f"\nFailed to parse tickets: {e}")
        logger.error(f"Failed to parse tickets: {e}")
        return


    print(f'\nProcessing tickets\n')
    logger.info(f'Processing tickets')
    file_time = time.time()
    responder = TicketResponder()
    responder.read_previous_entities()
    try:
        for ticket, entities in ticket_dict.items():
            print(f"\nProcessing {ticket}")
            for entity in entities:
                print(f'\nProcessing {entity.entity}')
                logger.info(f'Processing {entity.entity}')
                
                try:
                    print("Querying SPS intel")
                    logger.info("Querying SPS intel")
                    SpsIntelFetcher(entity)
                except Exception as e:
                    print(f"Failed to query intel for {entity.entity}: {e}")
                    logger.error(f"Failed to query intel for {entity.entity}: {e}")

                try:
                    print(f"Querying VT")
                    logger.info("Querying VT")
                    VirusTotalFetcher(entity)
                except Exception as e:
                    print(f"Failed to query VT for {entity.entity}: {e}")
                    logger.error(f"Failed to query VT for {entity.entity}: {e}")

                try:
                    print(f"Finding resolution")
                    logger.info("Finding resolution")
                    TicketResolver(entity, rule_set.rules, file_time)
                except Exception as e:
                    print(f"Failed to find resolution for {entity.entity}: {e}")
                    logger.error(f"Failed to finding resolution for {entity.entity}: {e}")
                
                try:
                    print(f"Generating entity specific response")
                    logger.info("Generating entity specific response")
                    ResponseCreator(entity)
                    print(f"Response generated")
                    logger.info("Response generated")
                except Exception as e:
                    print(f"Failed to generating ticket response for {entity.entity}: {e}")
                    logger.error(f"Failed to generating ticket response for {entity.entity}: {e}")

            try:
                print(f"Responding to {ticket}")
                logger.info(f"Responding to {ticket}")
                responder.update_responder(ticket, entities)
                responder.update_ticket()
            except Exception as e:
                print(f"Failed to respond to {ticket}: {e}")
                logger.error(f"Failed to respond to {ticket}: {e}")
    except Exception as e:
        print(f"\nFailed to process entities: {e}")
        logger.error(f"Failed to process entities: {e}")
        return
    
    try:
        print("\nCreating SPS Results Ticket")
        logger.info("Creating SPS Results Ticket")
        responder.create_sps_ticket()
    except Exception as e:
        print(f"\nFailed to create SPS automation results ticket: {e}")
        logger.error(f"Failed to create SPS automation results ticket: {e}")

    end_time = time.time()
    runtime = datetime.timedelta(seconds=end_time - start_time)
    # automation_logger = AutomationLogger(
    #     Entity.entity_list, responder, start_time, runtime
    # )
    # automation_logger.write_sps_data()

    # IntelProcessor(Entity.entity_list)
    logger.info("Process Finished...")
    logger.info("SPS ticket automation Finished")

def run_etp_process():
    ticket_dict = {}
    start_time = time.time()
    print("\n\nETP Ticket Automation In Progress...")
    logger.info("ETP Ticket Automation In Progress...")
    
    try:
        rule_set = RuleFetcher()
    except Exception as e:
        print(f"Failed to load Rule-Set: {e}")
        logger.error(f"Failed to load Rule-Set: {e}")
        return

    try:
        print("Initialising Mongo connection")
        logger.info("Initialising Mongo connection")
        mongo_connection = InitialiseMongo()
    except Exception as e:
        print(f"Failed to intialise Mongo connection: {e}")
        logger.error(f"Failed to intialise Mongo connection: {e}")
        return

    print("Fetching Tickets")
    try:
        tickets = TicketFetcher("etp").tickets
    except Exception as e:
        print(f"Failed to fetch tickets: {e}")
        logger.error(f"Failed to fetch tickets: {e}")
        return

    print("Parsing tickets")
    logger.info("Parsing tickets")
    try:
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
                    try:
                        entity = Entity(
                            "ETP", domain, entity_type, urls, ticket_id, ticket_type, reporter, is_guardicore_ticket, ips
                        )
                    except Exception as e:
                        print(f"Failed to create entity for {domain}: {e}")
                        logger.error(f"Failed to create entity for {domain}: {e}")
                        
                    if entity.append_entity is True:
                        if entity.ticket_id in ticket_dict:
                            ticket_dict[entity.ticket_id].append(entity)
                        else:
                            ticket_dict[entity.ticket_id] = [entity]
    except Exception as e:
        print(f"\nFailed to parse tickets: {e}")
        logger.error(f"Failed to parse tickets: {e}")
        return

    print(f'\nProcessing tickets\n')
    logger.info(f'Processing tickets')
    file_time = time.time()
    responder = TicketResponder()
    responder.read_previous_entities()
    try:
        for ticket, entities in ticket_dict.items():
            print(f"\nProcessing {ticket}")
            for entity in entities:
                print(f'\nProcessing {entity.entity}')
                logger.info(f'Processing {entity.entity}')
                
                try:
                    print("Querying ETP intel")
                    logger.info("Querying ETP intel")
                    EtpIntelFetcher(entity, mongo_connection)
                except Exception as e:
                    print(f"Failed to query intel for {entity.entity}: {e}")
                    logger.error(f"Failed to query intel for {entity.entity}: {e}")

                try:
                    print(f"Querying VT")
                    logger.info("Querying VT")
                    VirusTotalFetcher(entity)
                except Exception as e:
                    print(f"Failed to query VT for {entity.entity}: {e}")
                    logger.error(f"Failed to query VT for {entity.entity}: {e}")

                try:
                    print(f"Finding resolution")
                    logger.info("Finding resolution")
                    TicketResolver(entity, rule_set.rules, file_time)
                except Exception as e:
                    print(f"Failed to find resolution for {entity.entity}: {e}")
                    logger.error(f"Failed to finding resolution for {entity.entity}: {e}")
                
                try:
                    print(f"Generating entity specific response")
                    logger.info("Generating entity specific response")
                    ResponseCreator(entity)
                    print(f"Response generated")
                    logger.info("Response generated")
                except Exception as e:
                    print(f"Failed to generating ticket response for {entity.entity}: {e}")
                    logger.error(f"Failed to generating ticket response for {entity.entity}: {e}")
            try:
                print(f"Responding to {ticket}")
                logger.info(f"Responding to {ticket}")
                responder.update_responder(ticket, entities)
                responder.update_ticket()
            except Exception as e:
                print(f"Failed to respond to {ticket}: {e}")
                logger.error(f"Failed to respond to {ticket}: {e}")
    except Exception as e:
        print(f"Failed to process entities: {e}")
        logger.error(f"Failed to process entities: {e}")
        return
    
    try:
        print("\nCreating ETP Results Ticket")
        logger.info("Creating ETP Results Ticket")
        responder.create_etp_ticket()
    except Exception as e:
        print(f"\nFailed to create ETP automation results ticket: {e}")
        logger.error(f"Failed to create ETP automation results ticket: {e}")
    
    end_time = time.time()
    runtime = datetime.timedelta(seconds=end_time - start_time)
    # automation_logger = AutomationLogger(
    #     Entity.entity_list, responder, start_time, runtime
    # )
    # automation_logger.write_etp_data()
    # IntelProcessor(Entity.entity_list)
    print("\nETP ticket automation Finished")
    logger.info("ETP ticket automation Finished")


if __name__ == "__main__":
    args = parse_args()

    if args.queue.lower() not in ["sps", "etp"]:
        print("Please enter sps or etp to choose a queue!")
        exit(1)

    # try:
    #     if args.queue.lower() == "sps":
    # run_sps_process()
    run_etp_process()
    #     else:
    #         run_etp_process()
    # except Exception as e:
    #     print(f"Process Failed!... \nError: {e}")
    #     logger.error(f"Process Failed!... Error: {e}")

