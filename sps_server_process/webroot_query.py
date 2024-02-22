#!/usr/bin/python3


import subprocess


class Webroot:
    def __init__(self, domain) -> None:
        self.domain: str = domain
        self.get_webroot()

    def get_webroot(self):
        pattern = f"\s{self.domain}\s"

        cat_feed_process = subprocess.Popen(
            ["/usr/local/nom/bin/cat-feed", "--type", "text", "webroot/categories"],
            stdout=subprocess.PIPE,
        )

        grep_process = subprocess.Popen(
            ["grep", "-m", "1", pattern],
            stdin=cat_feed_process.stdout,
            stdout=subprocess.PIPE,
        )
        grep_decoded = grep_process.stdout.read()

        cut_data = subprocess.Popen(
            ["cut", "-f", "6"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        cut_result = cut_data.communicate(input=grep_decoded)[0]

        data = subprocess.Popen(
            ["cut", "-f", "2", "-d", ","],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        web_data = data.communicate(cut_result)[0]

        webroot_data = subprocess.Popen(
            ["cut", "-f", "2", "-d", ":"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        webroot = webroot_data.communicate(web_data)[0]
        webroot = webroot.decode("utf-8").replace("\n", "").replace("}", "")

        self.webroot = webroot
