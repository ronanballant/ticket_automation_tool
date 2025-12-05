class CarrierIntelLoader:
    previous_queries = {}

    def __init__(self, logger, client) -> None:
        self.logger = logger
        self.client = client
        self.results = None

    def read_previous_queries(self):
        try:
            self.results[self.indicator.candidate] = (
                CarrierIntelLoader.previous_queries.get(self.indicator.candidate, None)
            )
        except Exception as e:
            self.logger.error(f"Failed to read previous Intel query: {e}")
            raise

    def no_s3_intel(self):
        self.indicator.intel_feed = "-"
        self.indicator.intel_confidence = "-"
        self.indicator.intel_source = "-"
        self.indicator.confidence_level = "-"
        self.indicator.subdomain_count = 0
        self.indicator.url_count = 0
        self.indicator.is_in_intel = False
        self.indicator.e_list_entry = False
        self.indicator.subdomain_only = False
        CarrierIntelLoader.previous_queries[self.indicator.candidate] = {}

    def read_previous_s3_queries(self):
        try:
            self.result = CarrierIntelLoader.previous_queries.get(
                self.indicator.candidate, None
            )
        except Exception as e:
            self.logger.error(f"Failed to read previous Intel query: {e}")
            raise

    def query_s3_intel(self):
        self.result = self.client.query_fqdn(self.indicator.candidate)

    def assign_s3_intel(self):
        intel_feeds = []
        pairs = self.result.get("category_reason_pairs", [])
        for pair in pairs:
            feed, source = pair.split(":")
            intel_feeds.append((feed.strip(), source.strip()))

        intel_feeds.sort(key=lambda x: x[0], reverse=True)
        self.indicator.intel_feed_list = intel_feeds
        first_reason_pair = intel_feeds[0]
        first_feed = first_reason_pair[0].replace("|", "\|")
        first_source = first_reason_pair[1].replace("|", "\|")
        self.indicator.intel_feed = first_feed
        self.indicator.intel_source = first_source

        self.indicator.intel_confidence = self.result.get("max_confidence", "-")
        nps_cat = self.result.get("nps_cat", 0)
        if self.indicator.intel_confidence == "-" and nps_cat > 0:
            self.indicator.intel_confidence = nps_cat

        self.indicator.subdomain_count = self.result.get("subdomain_count", 0)
        self.indicator.url_count = self.result.get("path_count", "-")
        self.indicator.is_in_intel = True

        is_inexact = self.result.get("is_inexact", False)
        self.indicator.e_list_entry = not is_inexact
        self.indicator.subdomain_only = False
        CarrierIntelLoader.previous_queries[self.indicator.candidate] = self.result


def str_to_bool(string):
    if type(string) is str:
        return True if string.lower() == "true" else False
    else:
        return string
