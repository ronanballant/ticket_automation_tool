import json
import logging
import os
from datetime import datetime
import csv

import boto3
from config import (destination_region, directory_prefix, logger, results_path,
                    search_fqdns_path, secops_s3_aws_access_key,
                    secops_s3_aws_secret_key, secops_s3_bucket, secops_s3_endpoint, 
                    search_fqdns_local_file)

class S3Client:
    def __init__(
        self,
        destination_region,
        secops_s3_endpoint,
        secops_s3_bucket,
        secops_s3_aws_access_key,
        secops_s3_aws_secret_key,
        directory_prefix,
    ) -> None:
        self.destination_region = destination_region
        self.secops_s3_endpoint = secops_s3_endpoint
        self.secops_s3_bucket = secops_s3_bucket
        self.secops_s3_aws_access_key = secops_s3_aws_access_key
        self.secops_s3_aws_secret_key = secops_s3_aws_secret_key
        self.directory_prefix = directory_prefix
        self.endpoint_url = f"https://{self.secops_s3_endpoint}"

    def initialise_client(self):
        try:
            self.s3_client = boto3.client(
                "s3",
                endpoint_url=self.endpoint_url,
                aws_access_key_id=self.secops_s3_aws_access_key,
                aws_secret_access_key=self.secops_s3_aws_secret_key,
            )
        except Exception as e:
            logger.error(f"Failed to initialise S3 client: {e}")
            raise

    def collect_file_names(self):
        self.filenames = []
        continuation_token = None

        while True:
            if continuation_token:
                response = self.s3_client.list_objects_v2(
                    Bucket=self.secops_s3_bucket,
                    Prefix=self.directory_prefix,
                    ContinuationToken=continuation_token,
                )
            else:
                response = self.s3_client.list_objects_v2(
                    Bucket=self.secops_s3_bucket, Prefix=self.directory_prefix
                )

            if "Contents" in response:
                self.filenames.extend([obj["Key"] for obj in response["Contents"]])

            if response.get("IsTruncated"):
                continuation_token = response["NextContinuationToken"]
            else:
                logger.info(f"Collected {len(self.filenames)} files")
                break

    def get_new_filenames(self):
        self.new_filenames = self.filenames.copy()
        # if self.filenames:
        #     for file in self.filenames:
        #         filename = file.split("/")[-1]
        #         if filename.startswith("avtest_blacklist_") and filename.endswith('.csv'):
        #             ts = int(filename.replace("avtest_blacklist_", "").replace(".csv", ""))
        #             if ts >= self.last_hour_timestamp:
        #                 logger.info(f"File {file} added")
        #                 self.new_filenames.append(file)

        #     logger.info(f"Collected {len(self.new_filenames)} new files")
        # else:
        #     logger.error(f"No files collected")

    def read_s3_file(self, filename):
        response = self.s3_client.get_object(Bucket=self.secops_s3_bucket, Key=filename)
        self.file_content = response["Body"].read().decode("utf-8")

    def get_new_iocs(self):
        self.iocs = []
        self.broken_iocs = []

        for file_key in self.new_filenames:
            logger.info(f"new file key {file_key}")
            response = self.s3_client.get_object(
                Bucket=self.secops_s3_bucket, Key=file_key
            )
            file_content = response["Body"].read().decode("utf-8")
            ioc_strings = file_content.strip().split("\n")
            if ioc_strings:
                self.broken_iocs.extend(ioc_strings)

    def write_file(self, file_name, s3_output_path):
        logger.info(f"Writing {file_name} to {self.secops_s3_bucket}/{s3_output_path}")
        self.s3_client.upload_file(file_name, self.secops_s3_bucket, s3_output_path)

    def get_file(self, file_path):
        logger.info(f"Getting {file_path}")
        response = self.s3_client.get_object(
            Bucket=self.secops_s3_bucket, Key=file_path
        )
        self.file_content = response["Body"].read().decode("utf-8")
