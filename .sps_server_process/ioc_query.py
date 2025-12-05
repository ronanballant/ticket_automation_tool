from intel_query import Intel
from pi_cat_query import PiCat
from webroot_query import Webroot


class IocQuery:
    def __init__(self, domain) -> None:
        self.domain = domain
        # self.webroot = Webroot(domain).webroot
        # self.pi_cat = PiCat(domain).pi_category
        self.intel = Intel(domain)
