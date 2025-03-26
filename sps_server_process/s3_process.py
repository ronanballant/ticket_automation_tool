from s3_client import S3Client
import csv
import json
from ioc_query import IocQuery
from config import (destination_region, directory_prefix, empty_file_path, get_logger, results_path,
                    search_fqdns_path, secops_s3_aws_access_key,
                    secops_s3_aws_secret_key, secops_s3_bucket, secops_s3_endpoint, 
                    sps_intel_results_local_file, search_fqdns_local_file)


logger = get_logger("logs_s3_ticket_analyser.txt")


def get_domain_data(logger, domains):
    results = {}
    for domain in domains:
        logger.info(f"Searching intel for {domain}")
        result = IocQuery(domain)

        results[domain] = {
            "domain": result.domain,
            "intel_feed": result.intel.feed,
            "intel_confidence": result.intel.confidence,
            "intel_source": result.intel.source,
            "subdomain_count": result.intel.subdomain_count,
            "url_count": result.intel.url_count,
            "is_in_intel": result.intel.is_in_intel,
            "e_list_entry": result.intel.e_list_entry,
            "subdomain_only": result.intel.subdomain_only,
        }

    return results

logger.info("Starting S3 Ticket Analyser")
logger.info("Checking is_s3_running")
with open("is_s3_running.csv", "r") as file:
    lines = file.readlines()

    if "true" in lines[0]:
        logger.info(f"S3 Ticket Analyser currently running: {lines[0]}")
        exit()
    
with open("is_s3_running.csv", "w") as file:
    file.writelines("true")

logger.info(f"Initialising S3 client")
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
logger.info(f"Reading S3 file {search_fqdns_path}")
s3_client.read_s3_file(search_fqdns_path)
data = s3_client.file_content.strip().split("\n")
fqdns = [fqdn.strip().replace("[.]", ".") for fqdn in data]

if fqdns[0] == "empty":
    with open("is_s3_running.csv", "w") as file:
        file.writelines("false")
    logger.info(f"No FQDNs found... Exiting")
    exit()

logger.info(f"FQDNs found... \n{fqdns}")
with open("/home/azuser/secops_scripts/sps_ticket_automation/s3_results.json", "w") as file:
    file.writelines("")

results = get_domain_data(logger, fqdns)

logger.info(f"Writing empty file to {search_fqdns_local_file}")
with open(search_fqdns_local_file, "w") as file:
    writer = csv.writer(file)
    writer.writerow(["empty"])

logger.info(f"Writing empty S3 file to {search_fqdns_path}")
s3_client.write_file(search_fqdns_local_file, search_fqdns_path)

logger.info(f"Writing results file to /home/azuser/secops_scripts/sps_ticket_automation/s3_results.json")
with open("/home/azuser/secops_scripts/sps_ticket_automation/s3_results.json", "a") as file:
    json.dump(results, file, indent=4)

s3_client.write_file("/home/azuser/secops_scripts/sps_ticket_automation/s3_results.json", results_path)
s3_client.write_file(empty_file_path, search_fqdns_path)


logger.info(f"Writing 'false' to is_s3_running.csv")
with open("is_s3_running.csv", "w") as file:
    file.writelines("false")