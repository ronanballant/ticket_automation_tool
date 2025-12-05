import argparse
import boto3
import json


class S3FQDNLookup:
    def __init__(self, region, endpoint, bucket, access_key, secret_key):
        self.bucket = bucket
        self.prefix = "carrier_intel/first_letters="
        self.region = region
        self.s3 = boto3.client(
            "s3",
            region_name=region,
            endpoint_url=f"https://{endpoint}",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

    def query_fqdn(self, fqdn):
        first_letters = fqdn[:2].lower()
        prefix = f"{self.prefix}{first_letters}/"

        response = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        for obj in response.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(".json"):
                continue

            try:
                body = (
                    self.s3.get_object(Bucket=self.bucket, Key=key)["Body"]
                    .read()
                    .decode("utf-8")
                )

                for line in body.splitlines():
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        if record.get("fqdn") == fqdn:
                            return record
                    except json.JSONDecodeError:
                        continue

            except Exception:
                continue

        return None


def parse_args():
    parser = argparse.ArgumentParser(
        description="Query a single FQDN from S3 using DuckDB"
    )
    parser.add_argument(
        "-d",
        "--domain",
        default="suijidaohxl.top",
        help="Domain to query (e.g., a.mail.example.com)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    from config import (
        carrier_intel_region,
        carrier_intel_endpoint,
        carrier_intel_bucket,
        carrier_intel_access_key,
        carrier_intel_secret_key,
    )

    args = parse_args()
    client = S3FQDNLookup(
        carrier_intel_region,
        carrier_intel_endpoint,
        carrier_intel_bucket,
        carrier_intel_access_key,
        carrier_intel_secret_key,
    )
    result = client.query_fqdn(args.domain)
    print(result)
