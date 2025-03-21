from s3_client import S3Client
import csv
import json
from ioc_query import IocQuery
from config import (destination_region, directory_prefix, results_path,
                    search_fqdns_path, secops_s3_aws_access_key,
                    secops_s3_aws_secret_key, secops_s3_bucket, secops_s3_endpoint, 
                    sps_intel_results_local_file, search_fqdns_local_file)

def get_domain_data(domains):
    results = {}
    for domain in domains:
        print('domain', domain)
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

with open("is_s3_running.csv", "r") as file:
    lines = file.readlines()

    if "true" in lines[0]:
        exit()
    
with open("is_s3_running.csv", "w") as file:
    file.writelines("true")

s3_client = S3Client(
    destination_region,
    secops_s3_endpoint,
    secops_s3_bucket,
    secops_s3_aws_access_key,
    secops_s3_aws_secret_key,
    directory_prefix,
)
s3_client.initialise_client()
s3_client.read_s3_file(search_fqdns_path)
data = s3_client.file_content.strip().split("\n")
fqdns = [fqdn.strip().replace("[.]", ".") for fqdn in data]
if fqdns[0] == "empty":
    with open("is_s3_running.csv", "w") as file:
        file.writelines("false")
    exit()

with open("/home/azuser/secops_scripts/sps_ticket_automation/s3_results.json", "w") as file:
    file.writelines("")

results = get_domain_data(fqdns)
with open(search_fqdns_local_file, "w") as file:
    writer = csv.writer(file)
    writer.writerow(["empty"])

s3_client.write_file(search_fqdns_local_file, search_fqdns_path)

with open("/home/azuser/secops_scripts/sps_ticket_automation/s3_results.json", "a") as file:
    json.dump(results, file, indent=4)

s3_client.write_file("/home/azuser/secops_scripts/sps_ticket_automation/s3_results.json", results_path)

with open("is_s3_running.csv", "w") as file:
    file.writelines("false")