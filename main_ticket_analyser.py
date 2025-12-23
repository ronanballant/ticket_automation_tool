#!/usr/bin/python3

import argparse

from config import (
    ANALYSER_CERT_PATH,
    ANALYSER_KEY_PATH,
    ANALYSER_SSH_KEY_PATH,
    CARRIER_INTEL_BUCKET,
    CARRIER_INTEL_ENDPOINT,
    CARRIER_INTEL_REGION,
    LOGS_DIR,
    ETP_TICKETS_IN_PROGRESS_FILE,
    get_logger,
    SECOPS_MEMBER,
    SPS_TICKETS_IN_PROGRESS_FILE,
)
from s3_fqdn_lookup import S3FQDNLookup
from etp_intel_fetcher import ETPIntelFetcher
from indicator import Indicator
from initialise_mongo import InitialiseMongo
from key_handler import KeyHandler
from response_creator import ResponseCreator
from rule_fetcher import RuleFetcher
from carrier_intel_loader import CarrierIntelLoader
from ticket import Ticket
from ticket_fetcher import TicketFetcher
from ticket_resolver import TicketResolver
from ticket_responder import TicketResponder
from virus_total_fetcher import VirusTotalFetcher

logger = get_logger(str(LOGS_DIR / "ticket_analyser.log"))


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
        # default="ENTESC-17006",
        required=False,
        help="A comma seperated string of specific tickets to analyse",
    )
    args = parser.parse_args()

    if args.queue is None:
        """If no queue is selected"""
        parser.print_help()
        exit(1)
    else:
        return args

def query_carrier_intel(indicator, carrier_intel_fetcher, etp_check=False):
    try:
        logger.info("Querying SPS intel")
        carrier_intel_fetcher.indicator = indicator
        for candidate in indicator.candidates:
            indicator.matched_ioc_type = "DOMAIN"
            indicator.candidate = candidate
            carrier_intel_fetcher.read_previous_s3_queries()
            if carrier_intel_fetcher.result:
                carrier_intel_fetcher.assign_s3_intel(etp_check)
            else:
                carrier_intel_fetcher.query_s3_intel()
                if carrier_intel_fetcher.result:
                    carrier_intel_fetcher.assign_s3_intel(etp_check)
                else:
                    carrier_intel_fetcher.no_s3_intel()
                        

            if indicator.is_in_intel is True:
                indicator.matched_ioc = candidate
                break
            else:
                # Add IP functioinality
                # Add VT for matched candidate here
                pass
    except Exception as e:
        logger.error(f"Failed to query intel for {indicator.fqdn}: {e}")

def query_etp_intel(indicator, mongo_connection, vt_api_key, carrier_check=False):
    try:
        logger.info("Querying ETP intel")
        intel_fetcher = ETPIntelFetcher(
            logger, indicator, mongo_connection
        )

        for candidate in indicator.candidates:
            indicator.matched_ioc_type = "DOMAIN"
            indicator.candidate = (
                candidate + "." if candidate[-1] != "." else candidate
            )
            intel_fetcher.query_intel()
            intel_fetcher.assign_results(carrier_check)
            # if carrier intel, fetch carrier

            if indicator.is_in_intel is True:
                indicator.matched_ioc = indicator.candidate
                if indicator.matched_ioc != indicator.fqdn:
                    vt_fetcher = VirusTotalFetcher(
                        logger, indicator, indicator.matched_ioc[:-1], vt_api_key
                    )
                    vt_fetcher.prepare_indicator()
                    vt_fetcher.set_vt_link()
                    vt_fetcher.get_previous_query()
                    if not vt_fetcher.previous_vt_query:
                        vt_fetcher.rescan = False
                        vt_fetcher.get_external_data()
                        vt_fetcher.scan_domain()
                        vt_fetcher.analyse_vt_rescan()
                        vt_fetcher.save_results()
                        if vt_fetcher.indicator.has_vt_data is True:
                            vt_fetcher.get_domain_attributions()
                    if (
                        not vt_fetcher.previous_vt_query
                        and vt_fetcher.indicator.has_vt_data
                    ):
                        vt_fetcher.write_vt_data()
                break
            else:
                if carrier_check is False:
                    if indicator.ticket.ticket_type.lower() == "fp":
                        if candidate == indicator.candidates[-1]:
                            indicator.get_resolved_ip()

                            if indicator.resolved_ips:
                                intel_fetcher.query_resolved_ip()

                                if indicator.ip_in_intel is True:
                                    intel_fetcher.attributes_assigned = (
                                        False
                                    )
                                    intel_fetcher.assign_results(carrier_check)
                                    indicator.matched_ioc = (
                                        indicator.resolved_ip
                                    )
                                    indicator.matched_ioc_type = "IPV4"
    except Exception as e:
        logger.error(f"Failed to query intel for {indicator.fqdn}: {e}")

def ensure_single_period(s: str) -> str:
    s = s.strip()
    return s.rstrip('.') + '.'

def ensure_no_period(s: str) -> str:
    s = s.strip()
    return s.rstrip('.')

def run_process():
    queue = args.queue.lower()
    specified_tickets = args.tickets
    logger.info(f"{queue.upper()} Process In Progress...")
    tickets_in_progress_file = (
        SPS_TICKETS_IN_PROGRESS_FILE if queue == "sps" else ETP_TICKETS_IN_PROGRESS_FILE
    )

    logger.info("Fetching Keys")
    try:
        key_handler = KeyHandler(logger, ANALYSER_CERT_PATH, ANALYSER_KEY_PATH, ANALYSER_SSH_KEY_PATH)
        key_handler.get_key_names()
        key_handler.get_personal_keys()
        key_handler.get_vt_api_key()
        vt_api_key = key_handler.vt_api_key
        key_handler.get_carrier_intel_access_key()
        carrier_intel_access_key = key_handler.carrier_intel_access_key
        key_handler.get_carrier_intel_secret_key()
        carrier_intel_secret_key = key_handler.carrier_intel_secret_key
        key_handler.get_mongo_password()
        mongo_password = key_handler.mongo_password
    except Exception as e:
        logger.error(f"Failed to fetch keys: {e}")
        return

    logger.info("Fetching Tickets")
    try:
        ticket_fetcher = TicketFetcher(logger, ANALYSER_CERT_PATH, ANALYSER_KEY_PATH, queue)
        ticket_fetcher.get_tickets(specified_tickets)
        ticket_fetcher.parse_tickets()
        tickets = ticket_fetcher.tickets
    except Exception as e:
        logger.error(f"Failed to fetch tickets: {e}")
        return

    logger.info(f"Loading ticket data from {tickets_in_progress_file}")
    Ticket.load_ticket_data(tickets_in_progress_file)
    logger.info("Creating ticket instances")
    Ticket.get_tickets_in_progress()

    if not tickets:
        logger.info(f"No tickets in {queue.upper()} queue... exiting script")
        return
    logger.info("Collected %s tickets", len(tickets))

    try:
        rule_set = RuleFetcher(logger)
    except Exception as e:
        logger.error(f"Failed to load Rule-Set: {e}")
        return

    if queue == "etp":
        try:
            logger.info("Initialising Mongo connection")
            mongo_connection = InitialiseMongo(logger, mongo_password)
        except Exception as e:
            logger.error(f"Failed to intialise Mongo connection: {e}")
            return

    logger.info("Creating tickets")
    for ticket, values in tickets.items():
        in_progress = Ticket.tickets_in_progress.get(ticket, False)
        if in_progress is True:
            logger.info("Ticket already in progress")
            continue
        ips = values.get("ips")
        ticket_id = ticket
        fqdns = values.get("fqdns")
        urls = values.get("urls")
        ticket_type = values.get("ticket_type")
        reporter = values.get("reporter")
        indicator_type = values.get("indicator_type")
        is_guardicore_ticket = False
        creation_time = values.get("creation_time")

        if ticket_type == "FN" or ticket_type == "FP":
            new_ticket = Ticket(
                logger,
                ticket_id,
                ticket_type,
                queue.upper(),
                reporter,
                is_guardicore_ticket,
                fqdns,
                urls,
                ips,
                creation_time,
            )

            new_ticket.check_urls()
            new_ticket.set_process_flag()
            new_ticket.set_comment_greeting()
            new_ticket.set_comment_sign_off()

    for ticket in Ticket.all_tickets:
        logger.info("Processing %s tickets", len(Ticket.all_tickets))
        logger.info(f"Creating Indicator Instances for {ticket.ticket_id}")
        for fqdn in ticket.fqdns:
            indicator = Indicator(logger, fqdn, ticket, indicator_type)
            try:
                indicator.clean_fqdn()
                indicator.get_domain()
                indicator.get_etp_fqdn()
                indicator.is_whitelisted_domains()
                indicator.is_file_extension()
                indicator.is_legitimate_indicator()
                indicator.add_indicator_to_ticket()
                indicator.get_candidates()
            except Exception as e:
                logger.error(f"Failed to create indicator for {fqdn}: {e}")

    carrier_s3_client = S3FQDNLookup(
        CARRIER_INTEL_REGION,
        CARRIER_INTEL_ENDPOINT,
        CARRIER_INTEL_BUCKET,
        carrier_intel_access_key,
        carrier_intel_secret_key,
    )
    carrier_intel_fetcher = CarrierIntelLoader(logger, carrier_s3_client)

    responder = TicketResponder(logger, SECOPS_MEMBER, ANALYSER_CERT_PATH, ANALYSER_KEY_PATH)
    try:
        for ticket in Ticket.all_tickets:
            logger.info(f"Processing {ticket.ticket_id}")
            if not ticket.indicators:
                ticket.ticket_resolved = False
                ticket.block_comment = True
            for indicator in ticket.indicators:
                logger.info(f"Processing {indicator.fqdn}")

                try:
                    logger.info("Querying VT")
                    vt_fetcher = VirusTotalFetcher(logger, indicator, indicator.fqdn, vt_api_key)
                    vt_fetcher.prepare_indicator()
                    vt_fetcher.set_vt_link()
                    vt_fetcher.get_previous_query()
                    if not vt_fetcher.previous_vt_query:
                        vt_fetcher.rescan = False
                        vt_fetcher.scan_domain()
                        vt_fetcher.analyse_vt_rescan()
                        vt_fetcher.get_external_data()
                        vt_fetcher.save_results()
                        if vt_fetcher.indicator.has_vt_data is True:
                            vt_fetcher.get_domain_attributions()
                    if (
                        not vt_fetcher.previous_vt_query
                        and vt_fetcher.indicator.has_vt_data
                    ):
                        vt_fetcher.write_vt_data()

                    logger.info(f"VT indications:\t{indicator.vt_indications}")
                except Exception as e:
                    logger.error(f"Failed to query VT for {indicator.fqdn}: {e}")

                if queue == "sps":
                    query_carrier_intel(indicator, carrier_intel_fetcher)

                    if "etp" in indicator.intel_source.lower():
                        query_etp_intel(indicator, mongo_connection, vt_api_key, False)
                        indicator.matched_ioc  = ensure_no_period(indicator.matched_ioc or indicator.fqdn)

                else:
                    query_etp_intel(indicator, mongo_connection, vt_api_key)

                    if "nominum" in indicator.intel_source.lower():
                        logger.info("'nominum' in intel_source - quering Carrier intel")
                        query_carrier_intel(indicator, carrier_intel_fetcher, etp_check=True)
                        if indicator.etp_check_found is True:
                            indicator.intel_source_list.append(indicator.intel_source)
                            indicator.matched_ioc = ensure_single_period(indicator.matched_ioc or indicator.etp_fqdn)

                try:
                    logger.info("Finding resolution")
                    ticket_resolver = TicketResolver(logger, indicator, rule_set.rules)
                    ticket_resolver.prepare_fp_rule_query()
                    ticket_resolver.match_rule()
                except Exception as e:
                    logger.error(
                        f"Failed to finding resolution for {indicator.fqdn}: {e}"
                    )

                try:
                    logger.info("Generating indicator specific response")
                    response_creator = ResponseCreator(logger, indicator)
                    response_creator.generate_source_response()
                    response_creator.generate_comment_response()
                    logger.info("Response generated")
                except Exception as e:
                    logger.error(
                        f"Failed to generating ticket response for {indicator.fqdn}: {e}"
                    )
            try:
                logger.info(f"Responding to {ticket.ticket_id}")
                responder.update_ticket(ticket)
            except Exception as e:
                logger.error(f"Failed to respond to {ticket.ticket_id}: {e}")

            try:
                logger.info(f"Adding {ticket.ticket_id} to {tickets_in_progress_file}")
                ticket.update_tickets_in_progress(tickets_in_progress_file)
            except Exception as e:
                logger.error(
                    f"Failed to add {ticket.ticket_id} to {tickets_in_progress_file}: {e}"
                )
    except Exception as e:
        logger.error(f"Failed to process entities: {e}")
        return

    key_handler.remove_personal_keys()

    logger.info(f"{queue.upper()} ticket automation Finished")


if __name__ == "__main__":
    args = parse_args()

    if args.queue.lower() not in ["sps", "etp"]:
        print("Please enter sps or etp to choose a queue!")
        logger.error(f"{args.queue} is an invalid entry")
        exit(1)
    else:
        run_process()
