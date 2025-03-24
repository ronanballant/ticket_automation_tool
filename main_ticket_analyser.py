#!/usr/bin/python3

import argparse
import csv
import json
import os
import time

from config import (cert_path, etp_tickets_in_progress_file, key_path, logger,
                    secops_member, sps_tickets_in_progress_file, ssh_key_path,
                    destination_region, directory_prefix, results_path,
                    search_fqdns_path, secops_s3_aws_access_key,
                    secops_s3_aws_secret_key, secops_s3_bucket, secops_s3_endpoint, 
                    sps_intel_results_local_file, search_fqdns_local_file)
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


def parse_args():
    parser = argparse.ArgumentParser(description="Ticket Automation Tool")
    parser.add_argument(
        "-q",
        "--queue",
        default="sps",
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

def muc_server_process(fqdns, server_name):
    fqdns = list(set(fqdns))
    if "muc" in server_name:    
        s3_client = S3Client(
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
            print(fqdn)
            for fqdn in fqdns:
                writer.writerow([fqdn])

        print(f"\nwriting s3 file to {search_fqdns_path}")
        s3_client.write_file(search_fqdns_local_file, search_fqdns_path)
        s3_client.write_file(search_fqdns_local_file, results_path)
        
        recheck = True
        max_retries = 45
        retry_count = 0
        while recheck and retry_count < max_retries:
            time.sleep(60) 
            print(f"Atttempt {retry_count+1}")
            print(f"Reading S3 file")
            s3_client.read_s3_file(results_path)
            
            if s3_client.file_content:
                try:
                    json_results = json.loads(s3_client.file_content.strip())  # Strip spaces & newlines
                    if json_results:  # Check if it's a valid, non-empty JSON
                        recheck = False
                    else:
                        retry_count += 1
                except json.JSONDecodeError as e:
                    print(f"JSON Decode Error: {e} | Raw Data: {s3_client.file_content}")
                    retry_count += 1  # Keep retrying if JSON is invalid
            else:
                retry_count += 1  

        SPSIntelFetcher.previous_queries = json_results.copy()


def run_process():
    intel_search_fqdns = []
    queue = args.queue.lower()
    print(f"\n\n{queue.upper()} Ticket Automation In Progress...\n")
    logger.info(f"{queue.upper()} Process In Progress...")
    tickets_in_progress_file = sps_tickets_in_progress_file if queue == "sps" else etp_tickets_in_progress_file
    server_name = os.uname().nodename 

    print("\nFetching Keys")
    try:
        key_handler = KeyHandler(cert_path, key_path, ssh_key_path)
        key_handler.get_key_names()
        key_handler.get_personal_keys()
    except Exception as e:
        print(f"\nFailed to fetch keys: {e}")
        logger.error(f"Failed to fetch keys: {e}")
        return

    print("\nFetching Tickets")
    try:
        ticket_fetcher = TicketFetcher(cert_path, key_path, queue)
        ticket_fetcher.get_tickets()
        ticket_fetcher.parse_tickets()
        tickets = ticket_fetcher.tickets
    except Exception as e:
        print(f"\nFailed to fetch tickets: {e}")
        logger.error(f"Failed to fetch tickets: {e}")
        return

    if not tickets:
        logger.error(f"No tickets in {queue.upper()} queue")
        return

    try:
        rule_set = RuleFetcher()
    except Exception as e:
        print(f"\nFailed to load Rule-Set: {e}")
        logger.error(f"Failed to load Rule-Set: {e}")
        return

    if queue == "etp":
        try:
            print("Initialising Mongo connection")
            logger.info("Initialising Mongo connection")
            mongo_connection = InitialiseMongo()
        except Exception as e:
            print(f"Failed to intialise Mongo connection: {e}")
            logger.error(f"Failed to intialise Mongo connection: {e}")
            return

    print("Creating tickets")
    logger.info("Creating tickets")
    for ticket, values in tickets.items():
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
        logger.info(f"Creating Indicator Instances for {ticket.ticket_id}")
        print(f"\nCreating Indicator Instances for {ticket.ticket_id}")
        for fqdn in ticket.fqdns:
            indicator = Indicator(fqdn, ticket, indicator_type)
            try:
                indicator.clean_fqdn()
                indicator.get_domain()
                indicator.get_etp_fqdn()
                indicator.is_whitelisted_domains()
                indicator.is_file_extension()
                indicator.is_legitimate_indicator()
                indicator.add_indicator_to_ticket()
                indicator.get_candidates()
                if indicator.is_legitimate_indicator is True:
                    intel_search_fqdns.append(indicator.fqdn)
            except Exception as e:
                print(f"Failed to create indicator for {fqdn}: {e}")
                logger.error(f"Failed to create indicator for {fqdn}: {e}")

    if queue == "sps":
        muc_server_process(intel_search_fqdns, server_name)

    responder = TicketResponder(secops_member)
    try:
        for ticket in Ticket.all_tickets:
            print(f"\nProcessing {ticket.ticket_id}")
            for indicator in ticket.indicators:
                print(f"\nProcessing {indicator.fqdn}")
                logger.info(f"Processing {indicator.fqdn}")

                try:
                    print(f"Querying VT")
                    logger.info(f"Querying VT")
                    vt_fetcher = VirusTotalFetcher(indicator)
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

                    print(f"VT indications:\t{indicator.vt_indications}")
                    logger.info(f"VT indications:\t{indicator.vt_indications}")
                except Exception as e:
                    print(f"Failed to query VT for {indicator.fqdn}: {e}")
                    logger.error(f"Failed to query VT for {indicator.fqdn}: {e}")

                if queue == "sps":
                    try:
                        print("Querying SPS intel")
                        logger.info("Querying SPS intel")
                        intel_fetcher = SPSIntelFetcher(indicator)
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
                        print(f"Failed to query intel for {indicator.fqdn}: {e}")
                        logger.error(f"Failed to query intel for {indicator.fqdn}: {e}")
                else:
                    try:
                        print("Querying ETP intel")
                        logger.info("Querying ETP intel")
                        intel_fetcher = ETPIntelFetcher(indicator, mongo_connection)

                        for candidate in indicator.candidates:
                            indicator.matched_ioc_type = "DOMAIN"
                            indicator.candidate = (
                                candidate + "." if candidate[-1] != "." else candidate
                            )
                            intel_fetcher.query_intel()
                            intel_fetcher.assign_results()

                            if indicator.is_in_intel is True:
                                indicator.matched_ioc = indicator.candidate
                                break
                            else:
                                if candidate == indicator.candidates[-1]:
                                    indicator.get_resolved_ip()

                                    if indicator.resolved_ip:
                                        intel_fetcher.query_resolved_ip()

                                        if indicator.ip_in_intel is True:
                                            intel_fetcher.attributes_assigned = False
                                            intel_fetcher.assign_results()
                                            indicator.matched_ioc = (
                                                indicator.resolved_ip
                                            )
                                            indicator.matched_ioc_type = "IPV4"

                        if intel_fetcher.previous_intel is None:
                            intel_fetcher.write_intel_file()

                    except Exception as e:
                        print(f"Failed to query intel for {indicator.fqdn}: {e}")
                        logger.error(f"Failed to query intel for {indicator.fqdn}: {e}")

                try:
                    print(f"Finding resolution")
                    logger.info("Finding resolution")
                    ticket_resolver = TicketResolver(indicator, rule_set.rules)
                    ticket_resolver.prepare_fp_rule_query()
                    ticket_resolver.match_rule()
                except Exception as e:
                    print(f"Failed to find resolution for {indicator.fqdn}: {e}")
                    logger.error(
                        f"Failed to finding resolution for {indicator.fqdn}: {e}"
                    )

                try:
                    print(f"Generating indicator specific response")
                    logger.info("Generating indicator specific response")
                    response_creator = ResponseCreator(indicator)
                    response_creator.generate_source_response()
                    response_creator.generate_comment_response()

                    print(f"Response generated")
                    logger.info("Response generated")
                except Exception as e:
                    print(
                        f"Failed to generating ticket response for {indicator.fqdn}: {e}"
                    )
                    logger.error(
                        f"Failed to generating ticket response for {indicator.fqdn}: {e}"
                    )
            try:
                print(f"Responding to {ticket.ticket_id}")
                logger.info(f"Responding to {ticket.ticket_id}")
                responder.update_ticket(ticket)
            except Exception as e:
                print(f"Failed to respond to {ticket.ticket_id}: {e}")
                logger.error(f"Failed to respond to {ticket.ticket_id}: {e}")

            try:
                logger.info(f"Adding {ticket.ticket_id} to {tickets_in_progress_file}")
                ticket.update_tickets_in_progress(tickets_in_progress_file)
            except Exception as e:
                print(f"Failed to add {ticket.ticket_id} to {tickets_in_progress_file}: {e}")
                logger.error(f"Failed to add {ticket.ticket_id} to {tickets_in_progress_file}: {e}")
    except Exception as e:
        print(f"\nFailed to process entities: {e}")
        logger.error(f"Failed to process entities: {e}")
        return

    key_handler.remove_personal_keys()

    logger.info("Process Finished...")
    logger.info(f"{queue.upper()} ticket automation Finished")


if __name__ == "__main__":
    args = parse_args()

    if args.queue.lower() not in ["sps", "etp"]:
        print("Please enter sps or etp to choose a queue!")
        logger.error(f"{args.queue} is an invalid entry")
        exit(1)
    else:
        run_process()
