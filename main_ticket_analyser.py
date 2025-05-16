#!/usr/bin/python3

import argparse
import csv
import json
import os
import time
from typing import List

from config import (destination_region, directory_prefix,
                    etp_tickets_in_progress_file, get_logger, project_folder,
                    results_path, search_fqdns_local_file, search_fqdns_path,
                    secops_member, secops_s3_aws_access_key,
                    secops_s3_aws_secret_key, secops_s3_bucket,
                    secops_s3_endpoint, sps_intel_results_local_file,
                    sps_tickets_in_progress_file)
from etp_intel_fetcher import ETPIntelFetcher
from indicator import Indicator
from initialise_mongo import InitialiseMongo
from key_handler import KeyHandler
from response_creator import ResponseCreator
from rule_fetcher import RuleFetcher
from s3_client import S3Client
from sps_intel_fetcher import SPSIntelFetcher
from ticket import Ticket
from ticket_fetcher import TicketFetcher
from ticket_resolver import TicketResolver
from ticket_responder import TicketResponder
from virus_total_fetcher import VirusTotalFetcher

logger = get_logger("logs_ticket_analyser.txt")
cert_path = os.path.join(project_folder, ".ticket_analyser_personal_cert.crt")
key_path = os.path.join(project_folder, ".ticket_analyser_personal_key.key")
ssh_key_path = os.path.join(project_folder, ".ticket_analyser_ssh_key")


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
        default=None,
        required=False,
        help="A list of specific tickets to analyse",
    )
    args = parser.parse_args()

    if args.queue is None:
        """If no queue is selected"""
        parser.print_help()
        exit(1)
    else:
        return args



def muc_server_process(fqdns, server_name, key_handler):
    logger.info("Running on Muc server")
    fqdns = list(set(fqdns))

    if len(fqdns) < 1:
        logger.info("No IOCs to process... Exiting Process")
        key_handler.remove_personal_keys()
        exit()

    if "muc" in server_name:
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

        with open(search_fqdns_local_file, "w") as file:
            writer = csv.writer(file)
            for fqdn in fqdns:
                writer.writerow([fqdn])

        s3_client.write_file(search_fqdns_local_file, search_fqdns_path)
        s3_client.write_file(search_fqdns_local_file, results_path)

        recheck = True
        max_retries = 100
        retry_count = 0
        while recheck and retry_count < max_retries:
            time.sleep(60)
            logger.info(f"Atttempt {retry_count+1}")
            logger.info(f"Reading S3 file")
            s3_client.read_s3_file(results_path)

            if s3_client.file_content:
                try:
                    json_results = json.loads(
                        s3_client.file_content.strip()
                    )  # Strip spaces & newlines
                    if json_results:  # Check if it's a valid, non-empty JSON
                        recheck = False
                    else:
                        retry_count += 1
                except json.JSONDecodeError as e:
                    retry_count += 1  # Keep retrying if JSON is invalid
            else:
                retry_count += 1

        if retry_count > max_retries:
            logger.info("Retry count exceeded... Exiting script")

        SPSIntelFetcher.previous_queries = json_results.copy()


def run_process():
    intel_search_fqdns = []
    queue = args.queue.lower()
    specified_tickets = args.tickets
    logger.info(f"{queue.upper()} Process In Progress...")
    tickets_in_progress_file = (
        sps_tickets_in_progress_file if queue == "sps" else etp_tickets_in_progress_file
    )
    server_name = os.uname().nodename

    logger.info("Fetching Keys")
    try:
        key_handler = KeyHandler(logger, cert_path, key_path, ssh_key_path)
        key_handler.get_key_names()
        key_handler.get_personal_keys()
    except Exception as e:
        logger.error(f"Failed to fetch keys: {e}")
        return

    logger.info("Fetching Tickets")
    try:
        ticket_fetcher = TicketFetcher(logger, cert_path, key_path, queue)
        ticket_fetcher.get_tickets(specified_tickets)
        ticket_fetcher.parse_tickets()
        tickets = ticket_fetcher.tickets
    except Exception as e:
        logger.error(f"Failed to fetch tickets: {e}")
        return

    logger.info(f"Loading ticket data from {tickets_in_progress_file}")
    Ticket.load_ticket_data(tickets_in_progress_file)
    logger.info(f"Creating ticket instances")
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
            mongo_connection = InitialiseMongo(logger)
        except Exception as e:
            logger.error(f"Failed to intialise Mongo connection: {e}")
            return

    logger.info("Creating tickets")
    for ticket, values in tickets.items():
        in_progress = Ticket.tickets_in_progress.get(ticket, False)
        if in_progress is True:
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
                if indicator.legitimate_indicator is True:
                    logger.info(f"Adding {indicator.candidates} to intel search fqdns")
                    intel_search_fqdns += indicator.candidates
            except Exception as e:
                logger.error(f"Failed to create indicator for {fqdn}: {e}")

    if queue == "sps":
        muc_server_process(intel_search_fqdns, server_name, key_handler)

    responder = TicketResponder(logger, secops_member, cert_path, key_path)
    try:
        for ticket in Ticket.all_tickets:
            logger.info(f"Processing {ticket.ticket_id}")
            if not ticket.indicators:
                ticket.ticket_resolved = False
                ticket.block_comment = True
            for indicator in ticket.indicators:
                logger.info(f"Processing {indicator.fqdn}")

                try:
                    logger.info(f"Querying VT")
                    vt_fetcher = VirusTotalFetcher(logger, indicator, indicator.fqdn)
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

                    logger.info(f"VT indications:\t{indicator.vt_indications}")
                except Exception as e:
                    logger.error(f"Failed to query VT for {indicator.fqdn}: {e}")

                if queue == "sps":
                    try:
                        logger.info("Querying SPS intel")
                        intel_fetcher = SPSIntelFetcher(logger, indicator)
                        for candidate in indicator.candidates:
                            indicator.matched_ioc_type = "DOMAIN"
                            indicator.candidate = candidate
                            intel_fetcher.read_previous_queries()
                            if not intel_fetcher.results and "muc" not in server_name:
                                intel_fetcher.fetch_intel()
                            intel_fetcher.assign_results()

                            if indicator.is_in_intel is True:
                                indicator.matched_ioc = candidate
                                break
                    except Exception as e:
                        logger.error(f"Failed to query intel for {indicator.fqdn}: {e}")
                else:
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
                            intel_fetcher.assign_results()

                            if indicator.is_in_intel is True:
                                indicator.matched_ioc = indicator.candidate
                                if indicator.matched_ioc != indicator.fqdn:
                                    vt_fetcher = VirusTotalFetcher(
                                        logger, indicator, indicator.matched_ioc[:-1]
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
                                if indicator.ticket.ticket_type.lower() == "fp":
                                    if candidate == indicator.candidates[-1]:
                                        indicator.get_resolved_ip()

                                        if indicator.resolved_ips:
                                            intel_fetcher.query_resolved_ip()

                                            if indicator.ip_in_intel is True:
                                                intel_fetcher.attributes_assigned = (
                                                    False
                                                )
                                                intel_fetcher.assign_results()
                                                indicator.matched_ioc = (
                                                    indicator.resolved_ip
                                                )
                                                indicator.matched_ioc_type = "IPV4"
                    except Exception as e:
                        logger.error(f"Failed to query intel for {indicator.fqdn}: {e}")

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
