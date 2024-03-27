import argparse

from ioc_query import IocQuery


def parse_args():
    parser = argparse.ArgumentParser(description="provide a list of domains to query")
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="file containing a list of domains to query",
    )
    parser.add_argument(
        "-d",
        "--domains",
        type=str,
        help="A list of domains to query",
    )
    args = parser.parse_args()

    if args.file is None and args.domains is None:
        """If both file and domain inputs are empty"""
        parser.print_help()
        exit(1)
    else:
        return args


def parse_file(file):
    with open(file, "r") as f:
        domain_list = [line.strip() for line in f]

    return domain_list


def prepare_domains(domains):
    domain_list = domains.split(",")
    filtered_list = []

    for x in range(0, len(domain_list)):
        domain_list[x] = (
            domain_list[x]
            .replace("'", "")
            .replace('"', "")
            .replace("[", "")
            .replace("]", "")
            .replace(" ", "")
            .replace("/", "")
            .replace("\\", "")
            .replace("=", "")
            .replace("<", "")
            .replace(">", "")
            .replace("?", "")
        )

        filtered_list.append(domain_list[x])

    return filtered_list


def get_domain_data(domains):
    for domain in domains:
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
        }
        # "webroot": result.webroot,

    return results


if __name__ == "__main__":
    results = {}
    args = parse_args()

    if args.domains is None:
        try:
            domains = parse_file(args.file)
        except FileNotFoundError:
            print(f"Could not find file {args.file}")
            exit(1)
        domains = prepare_domains(domains)
    else:
        domains = prepare_domains(args.domains)

    results = get_domain_data(domains)

    print(results)
