from pymongo import MongoClient

from config import MONGO_PREFIX, MONGO_URI


class InitialiseMongo:
    def __init__(self, logger, mongo_password) -> None:
        self.logger = logger
        self.mongo_db_cred = f"{MONGO_PREFIX}{mongo_password}{MONGO_URI}"
        self.mongo_db_cred = "mongodb://secops:C3fQW5ZayVpE3BK8@prod-galaxy-t4tools.dfw02.corp.akamai.com:27017/indicators?authSource=secops"
        # self.mongo_db_cred = tb_cred.login["mongo_int"]
        self.client = MongoClient(self.mongo_db_cred)
        self.client.server_info()
        self.db = self.client.secops
        self.blacklist = self.db.blacklist

