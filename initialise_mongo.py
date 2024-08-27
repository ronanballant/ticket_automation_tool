from pymongo import MongoClient

import tb_cred


class InitialiseMongo:
    def __init__(self) -> None:
        self.mongo_db_cred = tb_cred.login["mongo_int"]
        self.client = MongoClient(self.mongo_db_cred)
        self.client.server_info()
        self.db = self.client.secops
        self.blacklist = self.db.blacklist
