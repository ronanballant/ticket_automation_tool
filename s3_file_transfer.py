from xml import dom
import boto3
import duckdb
import json




class S3FileTransfer:
    def __init__(self, region, endpoint, bucket, access_key, secret_key):
        self.region = region
        self.endpoint = endpoint
        self.bucket = bucket
        self.access_key  = access_key 
        self.secret_key = secret_key
        self.connection = duckdb.connect()
        self.create_s3_client()
        self.configure_s3()

    def create_s3_client(self):
        self.s3_client = boto3.client(
            's3',
            endpoint_url=f"https://{self.endpoint}",
            region_name=self.region,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key
        )

    def configure_s3(self):
        self.connection.execute("INSTALL httpfs;")
        self.connection.execute("LOAD httpfs;")
        self.connection.execute(f"SET s3_region='{self.region}';")
        self.connection.execute(f"SET s3_endpoint='{self.endpoint}'")
        self.connection.execute(f"SET s3_access_key_id='{self.access_key}';")
        self.connection.execute(f"SET s3_secret_access_key='{self.secret_key}';")

    def list_files(self, prefix):
        continuation_token = None
        file_list = []
            
        list_objects_params = {
            'Bucket': self.bucket,
            'Prefix': prefix
        }

        while True:
            if continuation_token:
                list_objects_params['ContinuationToken'] = continuation_token

            response = self.s3_client.list_objects_v2(**list_objects_params)
            
            for obj in response.get('Contents', []):
                file_list.append(obj['Key'])
            
            if response.get('IsTruncated'):  
                continuation_token = response['NextContinuationToken']
            else:
                break
        
        self.all_files = file_list

    def load_intel_data(self):
        fqdn_dict = {}
        for file in self.all_files:
            s3_response = self.s3_client.get_object(Bucket=self.bucket, Key=file)
            lines = s3_response['Body'].read().decode('utf-8').splitlines()
            
            for line in lines:
                try:
                    record = json.loads(line)
                    fqdn = record.get('fqdn')
                    fqdn_dict[fqdn] = record
                except json.JSONDecodeError:
                    continue

        self.fqdn_dict = fqdn_dict


    def load_data(self):
        fqdn_dict = {}
        trie = DomainTrie()
        for file in self.all_files:
            s3_response = self.s3_client.get_object(Bucket=self.bucket, Key=file)
            lines = s3_response['Body'].read().decode('utf-8').splitlines()
            for line in lines:
                try:
                    record = json.loads(line)
                    fqdn = record.get('fqdn')
                    trie.insert(fqdn, data=record)
                except json.JSONDecodeError:
                    continue

        self.trie = trie
        