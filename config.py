#!/usr/bin/python3
import os
from pathlib import Path
from logger import logging


PROJECT_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
SERVER_NAME = os.uname().nodename 
if "prod-galaxy-t4tools01" in SERVER_NAME:
    DATA_DIR = Path("/app01/secops/data/ticket_automation/")
    LOGS_DIR = Path("/app01/secops/log/ticket_automation/")
    ETP_INTEL_REPO = Path("/app01/secops/repos/sia-secops-TCSI/etp-threat-intel-config/archive-root/akamai/etp/threat-intel-config/config/")
    SECOPS_FEED_DIRECTORY = ETP_INTEL_REPO /"secops-feed"
else:
    DATA_DIR = PROJECT_DIR / "data"
    LOGS_DIR = PROJECT_DIR / "log"
    ETP_INTEL_REPO = Path("/Users/rballant/work/etp/etp-threat-intel-config/archive-root/akamai/etp/threat-intel-config/config/")
    DOCKER_IMAGES = Path("/Users/rballant/work/secops/prod-galaxy-t4tools/app01/docker_images")
    SECOPS_FEED_DIRECTORY = ETP_INTEL_REPO / "secops-feed"


# Project Config
SECOPS_MEMBER = "rballant"
PREVIOUS_QUERIES_FILE = DATA_DIR / "previous_vt_queries.csv"
RULE_PATH = DATA_DIR / "rule_table.csv"
SPS_TICKETS_IN_PROGRESS_FILE = DATA_DIR / "sps_tickets_in_progress.json"
SPS_PROCESSED_TICKETS_FILE = DATA_DIR / "sps_processed_tickets.json"
ETP_TICKETS_IN_PROGRESS_FILE = DATA_DIR / "etp_tickets_in_progress.json"
ETP_PROCESSED_TICKETS_FILE = DATA_DIR / "etp_processed_tickets.json"
OPEN_SPS_SUMMARY_TICKETS_FILE = DATA_DIR / "open_sps_summary_tickets.csv"
OPEN_ETP_SUMMARY_TICKETS_FILE = DATA_DIR / "open_etp_summary_tickets.csv"
DASHBOARD_TICKET_FILE = DATA_DIR / "dashboard_tickets.json"

CARRIER_INTEL_REGION = "us-iad-5"
CARRIER_INTEL_ENDPOINT = "us-iad-5.linodeobjects.com"
CARRIER_INTEL_BUCKET = "esg-secops-discovery-week"
FEED_PROCESSOR_URL = "https://freshmilk.prod-us-ord.prod.spof.akaetp.net/api/v1/entry/add"
FEED_PROCESSOR_URL2 = "https://freshmilk.prod-us-sea.prod.spof.akaetp.net/api/v1/entry/add"
PRIVATE_KEY_PATH = "~/.ssh/azvmcommon"
JUMP_HOST_USERNAME = "azuser"
JUMP_HOST_IP = "20.232.62.46"
DESTINATION_USERNAME = "azuser"
DESTINATION_IP = "172.27.9.9"
SECOPS_VAULT = "https://secops4kv.vault.azure.net/"
JIRA_SEARCH_API = "https://track-api.akamai.com/jira/rest/api/2/search"
JIRA_TICKET_API = "https://track-api.akamai.com/jira/rest/api/2/issue/"
INTERAL_VT_API = "http://172.233.237.203:8081/api/vt-category?domain="

# SecOps Key Vault
RBALLANT_CERT_NAME = "rballant-crt"
RBALLANT_KEY_NAME = "rballant-key"
RBALLANT_SSH_KEY_NAME = "rballant-ssh"
VT_API_KEY_NAME = "ronan-vt-api"
CARRIER_INTEL_ACCESS_KEY_NAME = "carrier-ti-access"
CARRIER_INTEL_SECRET_KEY_NAME = "carrier-ti-secret"
FEED_PROCESSOR_API_KEY_NAME = "feed-processor-api"
MONGO_PASSWORD_NAME = "mongo-root"

MONGO_PREFIX = f'mongodb://root:'
MONGO_URI = '@localhost:27017/?authSource=admin'

WHITELIST_FILE = ETP_INTEL_REPO / "manual_whitelist.csv"
BLACKLIST_FILE = ETP_INTEL_REPO / "manual_blacklist.csv"
SECOPS_FEED_FILE = ETP_INTEL_REPO / "secops-feed" / "manual_secops_feed_additions.csv"

# # Mongo Config 
# MONGO_NAME = "mongosecops"
# MONGO_NAME_AUP = "mongoaup"
# # mongosecops
# MONGO_USERNAME = "secops-adm"
# MONGO_HOST = "prod-galaxy-t4tools.dfw02.corp.akamai.com"
# MONGO_PORT = 27017
# MONGO_DATABASE = "secops"
# # mongoaup
# MONGO_USERNAME_AUP = "aup-read"
# MONGO_HOST_AUP = "prod-galaxy-t4tools.dfw02.corp.akamai.com"
# MONGO_PORT_AUP = 27017
# MONGO_DATABASE_AUP = "aup"

LOG_LEVEL = logging.INFO

def get_logger(log_filename=str(LOGS_DIR / "ticket_automation.log")):
    log_path = Path(log_filename) if log_filename else (LOGS_DIR / "ticket_automation.log")
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("ticket_automation")
    logger.setLevel(LOG_LEVEL)
    logger.propagate = False 

    if not logger.handlers:
        try:
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3, encoding="utf-8")
        except Exception:
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setLevel(LOG_LEVEL)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(LOG_LEVEL)

        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
        file_handler.setFormatter(fmt)
        console_handler.setFormatter(fmt)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger