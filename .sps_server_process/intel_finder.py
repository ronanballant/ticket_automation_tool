#!/usr/bin/python3

import subprocess


class IntelFinder:
    def __init__(self, domain) -> None:
        self.domain: str = domain

    def get_intel_feed(self):
        pattern = f"\s{self.domain}\s"
        cat_feed_process = subprocess.Popen(
            [
                "/usr/local/nom/bin/cat-feed",
                "--type",
                "pmlist",
                "gix_vta_block_i",
                "tpsvc_malware_lv5_i",
                "tpsvc_phishing_lv5_i",
                "tpsvc_unidentified_lv5_i",
                "tpsvc_malware_lv4_i",
                "tpsvc_phishing_lv4_i",
                "tpsvc_unidentified_lv4_i",
                "tpsvc_malware_lv3_i",
                "tpsvc_phishing_lv3_i",
                "tpsvc_unidentified_lv3_i",
                "tps_malware_i",
                "tps_phishing_i",
            ],
            stdout=subprocess.PIPE,
        )

        grep_process = subprocess.Popen(
            ["grep", pattern],
            stdin=cat_feed_process.stdout,
            stdout=subprocess.PIPE,
        )
        grep_decoded = grep_process.stdout.read()

        cut_feed = subprocess.run(
            ["cut", "-f", "8"], input=grep_decoded, stdout=subprocess.PIPE
        )
        feed = cut_feed.stdout.decode("utf-8").replace("\n", "")

        cut_data = subprocess.Popen(
            ["cut", "-f", "6"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
        )
        data, err = cut_data.communicate(grep_decoded)

        source_string = subprocess.run(
            ["cut", "-d", '"', "-f", "6"], input=data, stdout=subprocess.PIPE
        )
        source = source_string.stdout.decode("utf-8").replace("\n", "")

        confidence_string = subprocess.run(
            ["cut", "-d", '"', "-f", "3"], input=data, stdout=subprocess.PIPE
        )
        confidence = (
            confidence_string.stdout.decode("utf-8")
            .replace("\n", "")
            .replace(":", "")
            .replace(",", "")
        )

        self.feed = feed
        self.confidence = confidence
        self.source = source
