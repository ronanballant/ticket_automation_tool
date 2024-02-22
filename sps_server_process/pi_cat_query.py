#!/usr/bin/python3

import subprocess


class PiCat:
    def __init__(self, domain) -> None:
        self.domain: str = domain
        self.get_pi_cat()

    def get_pi_cat(self):
        pattern = f"\s{self.domain}\s"
        cat_feed_process = subprocess.Popen(
            [
                "/usr/local/nom/bin/cat-feed",
                "--type",
                "pmlist",
                "ads_i",
                "alc_tob_i",
                "anon_i",
                "arts_i",
                "business_i",
                "cdns_i",
                "chat_i",
                "chat_scsvc_facebookmessenger_i",
                "chat_scsvc_googlehangout_i",
                "chat_scsvc_skype_i",
                "chat_scsvc_whatsapp_i",
                "cheating_i",
                "child_abuse_i",
                "commerce_e",
                "community_e",
                "community_scsvc_facebook_e",
                "community_scsvc_googleplus_e",
                "community_scsvc_googleplus_i",
                "community_scsvc_instagram_i",
                "community_scsvc_musicaldotly_i",
                "community_scsvc_pinterest_i",
                "community_scsvc_reddit_i",
                "community_scsvc_snapchat_i",
                "community_scsvc_tumblr_i",
                "community_scsvc_twitter_i",
                "crime_i",
                "cults_i",
                "data_prot_i",
                "dotdoh_i",
                "drugs_i",
                "edu_i",
                "effective_tlds_i",
                "entertain_i",
                "errors_i",
                "fashion_i",
                "food_i",
                "forums_i",
                "gambling_i",
                "games_i",
                "gov_i",
                "greet_i",
                "hacking_i",
                "hate_i",
                "health_i",
                "homepage_i",
                "images_i",
                "jobs_i",
                "lingerie_i",
                "money_i",
                "news_i",
                "nonprof_i",
                "nudity_i",
                "offensive_i",
                "p2p_i",
                "parked_i",
                "personals_i",
                "politics_i",
                "porn_i",
                "realty_i",
                "recreation_i",
                "religion_i",
                "rfc1918_i",
                "safec_google_search_i",
                "safec_youtube_service_i",
                "safe_to_message_i",
                "safe_to_proxy_i",
                "search_i",
                "search_scsvc_bing_i",
                "search_scsvc_duckduckgo_i",
                "search_scsvc_google_i",
                "self_harm_i",
                "sex_ed_i",
                "software_i",
                "sports_i",
                "stream_i",
                "stream_scsvc_amazonmusic_i",
                "stream_scsvc_amazonvideo_i",
                "stream_scsvc_applemusic_i",
                "stream_scsvc_deezer_i",
                "stream_scsvc_googleplaymusic_i",
                "stream_scsvc_hulu_i",
                "stream_scsvc_netflix_i",
                "stream_scsvc_shazam_i",
                "stream_scsvc_soundcloud_i",
                "stream_scsvc_spotify_i",
                "stream_scsvc_tidal_i",
                "stream_scsvc_vevo_i",
                "stream_scsvc_vimeo_i",
                "stream_scsvc_youtube_i",
                "tech_i",
                "tls_never_terminate_i",
                "translate_i",
                "travel_i",
                "vehicles_i",
                "violence_i",
                "warez_i",
                "weapons_i",
                "webmail_i",
            ],
            stdout=subprocess.PIPE,
        )

        grep_process = subprocess.Popen(
            ["grep", pattern],
            stdin=cat_feed_process.stdout,
            stdout=subprocess.PIPE,
        )
        grep_decoded = grep_process.stdout.read()

        cut_data = subprocess.Popen(
            ["cut", "-d", "\t", "-f", "6"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        cut_result = cut_data.communicate(input=grep_decoded)[0]

        data = subprocess.Popen(
            ["cut", "-f", "1", "-d", ","],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        cat_data = data.communicate(cut_result)[0]

        cat_list = subprocess.Popen(
            ["cut", "-f", "2", "-d", ":"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        category = cat_list.communicate(cat_data)[0]
        category = category.decode("utf-8").strip()

        self.pi_category = category
