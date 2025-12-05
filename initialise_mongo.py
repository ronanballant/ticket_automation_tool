from pymongo import MongoClient

from config import mongo_prefix, mongo_uri


class InitialiseMongo:
    def __init__(self, logger, mongo_password) -> None:
        self.logger = logger
        self.mongo_db_cred = f"{mongo_prefix}{mongo_password}{mongo_uri}"
        # self.mongo_db_cred = tb_cred.login["mongo_int"]
        self.client = MongoClient(self.mongo_db_cred)
        self.client.server_info()
        self.db = self.client.secops
        self.blacklist = self.db.blacklist

