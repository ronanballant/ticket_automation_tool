#!/usr/bin/python3

import subprocess


class Intel:
    def __init__(self, domain) -> None:
        self.domain: str = domain
        self.get_intel_feed()

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
                "tpsvc_spam_lv5_i",
                "tpsvc_spam_lv4_i",
                "tpsvc_spam_lv3_i",
            ],
            stdout=subprocess.PIPE,
        )

        grep_process = subprocess.Popen(
            ["grep", "-m 1", pattern],
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
        self.is_in_intel = True if self.feed else False
        self.e_list_entry = False

        if self.is_in_intel is False:
            e_cat_feed_process = subprocess.Popen(
                [
                    "/usr/local/nom/bin/cat-feed",
                    "--type",
                    "pmlist",
                    "tpsvc_malware_lv5_e",
                    "tpsvc_phishing_lv5_e",
                    "tpsvc_unidentified_lv5_e",
                    "tpsvc_malware_lv4_e",
                    "tpsvc_phishing_lv4_e",
                    "tpsvc_unidentified_lv4_e",
                    "tpsvc_malware_lv3_e",
                    "tpsvc_phishing_lv3_e",
                    "tpsvc_unidentified_lv3_e",
                ],
                stdout=subprocess.PIPE,
            )

            e_grep_process = subprocess.Popen(
                ["grep", "-m 1", pattern],
                stdin=e_cat_feed_process.stdout,
                stdout=subprocess.PIPE,
            )
            e_grep_decoded = e_grep_process.stdout.read()

            e_cut_feed = subprocess.run(
                ["cut", "-f", "8"], input=e_grep_decoded, stdout=subprocess.PIPE
            )
            e_feed = e_cut_feed.stdout.decode("utf-8").replace("\n", "")

            e_cut_data = subprocess.Popen(
                ["cut", "-f", "6"], stdin=subprocess.PIPE, stdout=subprocess.PIPE
            )
            e_data, err = e_cut_data.communicate(e_grep_decoded)

            e_source_string = subprocess.run(
                ["cut", "-d", '"', "-f", "6"], input=e_data, stdout=subprocess.PIPE
            )
            e_source = e_source_string.stdout.decode("utf-8").replace("\n", "")

            e_confidence_string = subprocess.run(
                ["cut", "-d", '"', "-f", "3"], input=e_data, stdout=subprocess.PIPE
            )
            e_confidence = (
                e_confidence_string.stdout.decode("utf-8")
                .replace("\n", "")
                .replace(":", "")
                .replace(",", "")
            )

            self.feed = e_feed
            self.confidence = e_confidence
            self.source = e_source
            self.is_in_intel = True if self.feed else False
            self.e_list_entry = True
