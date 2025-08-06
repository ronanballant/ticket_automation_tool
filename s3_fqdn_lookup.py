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
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )

    def query_fqdn(self, fqdn):
        first_letters = fqdn[:2].lower()
        prefix = f"{self.prefix}{first_letters}/"

        response = self.s3.list_objects_v2(Bucket=self.bucket, Prefix=prefix)
        if "Contents" not in response:
            return None

        for obj in response["Contents"]:
            key = obj["Key"]
            if not key.endswith(".json"):
                continue

            obj_data = self.s3.get_object(Bucket=self.bucket, Key=key)
            json_data = json.load(obj_data["Body"]) 

            for entry in json_data:
                if fqdn in entry:
                    return entry[fqdn]  

        return None

def parse_args():
    parser = argparse.ArgumentParser(description="Query a single FQDN from S3 using DuckDB")
    parser.add_argument("-d", "--domain", default="suijidaohxl.top", help="Domain to query (e.g., a.mail.example.com)")
    return parser.parse_args()

