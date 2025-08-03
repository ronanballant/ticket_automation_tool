import argparse
import duckdb
import time


class DuckDBFQDNLookup:
    def __init__(self, region, endpoint, bucket, access_key, secret_key):
        self.bucket = bucket
        self.prefix = "carrier_intel/first_letters="
        self.region = region
        self.endpoint = endpoint
        self.access_key = access_key
        self.secret_key = secret_key

        self.conn = duckdb.connect()
        self._configure_s3()

    def _configure_s3(self):
        self.conn.execute("INSTALL httpfs;")
        self.conn.execute("LOAD httpfs;")
        self.conn.execute(f"SET s3_region='{self.region}';")
        self.conn.execute(f"SET s3_endpoint='{self.endpoint}';")
        self.conn.execute(f"SET s3_access_key_id='{self.access_key}';")
        self.conn.execute(f"SET s3_secret_access_key='{self.secret_key}';")

    def query_fqdn(self, fqdn):
        first_letters = fqdn[:2].lower()
        s3_path = f"s3://{self.bucket}/{self.prefix}{first_letters}/*.json"

        query = f"""
        SELECT * FROM read_json_auto('{s3_path}')
        WHERE fqdn = '{fqdn}'
        LIMIT 1
        """
        result_df = self.conn.execute(query).fetchdf()

        if result_df.empty:
            return None
        return result_df.iloc[0].to_dict()


def parse_args():
    parser = argparse.ArgumentParser(description="Query a single FQDN from S3 using DuckDB")
    parser.add_argument("-d", "--domain", default="suijidaohxl.top", help="Domain to query (e.g., a.mail.example.com)")
    return parser.parse_args()

