import time

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


def run_sps_process():
    logger.info("SPS Process In Progress...")
    tickets = TicketFetcher("sps").tickets
    for ticket, values in tickets.items():
        ticket_id = ticket
        domains = values.get("domains")
        urls = values.get("urls")
        ticket_type = values.get("ticket_type")
        reporter = values.get("reporter")
        entity_type = values.get("entity_type")

        if ticket_type == "FN" or ticket_type == "FP":
            for domain in domains:
                Entity("SPS", domain, entity_type, urls, ticket_id, ticket_type, reporter)

    SpsIntelFetcher(Entity.entity_list)

    rule_set = RuleFetcher()
    file_time = time.time()
    for entity in Entity.entity_list:
        VirusTotalFetcher(entity)
        TicketResolver(entity, rule_set.rules, file_time)
        ResponseCreator(entity)

    responder = TicketResponder(Entity.entity_list)
    responder.create_sps_ticket()
    responder.update_tickets()
    # responder.save_unresolved_domains()
    # IntelProcessor(Entity.entity_list)


def run_etp_process():
    logger.info("ETP Process In Progress...")
    tickets = TicketFetcher("etp").tickets
    for ticket, values in tickets.items():
        ticket_id = ticket
        domains = values.get("domains")
        urls = values.get("urls")
        ticket_type = values.get("ticket_type")
        reporter = values.get("reporter")
        entity_type = values.get("entity_type")

        if ticket_type == "FN" or ticket_type == "FP":
            for domain in domains:
                Entity("ETP", domain, entity_type, urls, ticket_id, ticket_type, reporter)

    EtpIntelFetcher(Entity.entity_list)

    file_time = time.time()
    for entity in Entity.entity_list:
        VirusTotalFetcher(entity)
        TicketResolver(entity, file_time)
        ResponseCreator(entity)

    responder = TicketResponder(Entity.entity_list)
    responder.create_etp_ticket()
    responder.update_tickets()
    # responder.save_unresolved_domains()
    # IntelProcessor(Entity.entity_list)


if __name__ == "__main__":
    try:
        run_sps_process()
        # run_etp_process()
    except Exception as e:
        logger.error(f"Process Failed!... Error: {e}")
