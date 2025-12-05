class TicketResolver:
    DAYS_SINCE_CREATION = 30  # days since creation

    def __init__(self, logger, indicator, rules) -> None:
        self.logger = logger
        self.indicator = indicator
        self.rules = rules

    def prepare_fp_rule_query(self):
        self.logger.info("Preparing data for rule matching")

        if self.indicator.ticket.queue == "SPS":
            self.indicator.is_filtered = "-"
            self.indicator.intel_category_strength = "-"

            if self.indicator.is_in_intel is True:
                if (
                    self.indicator.intel_confidence
                    and self.indicator.intel_confidence != "-"
                ):
                    if self.indicator.intel_confidence >= 0.90:
                        self.indicator.confidence_level = 5
                    elif self.indicator.intel_confidence >= 0.80:
                        self.indicator.confidence_level = 4
                    elif self.indicator.intel_confidence >= 0.70:
                        self.indicator.confidence_level = 3
                    elif self.indicator.intel_confidence >= 0.60:
                        self.indicator.confidence_level = 2
                    elif self.indicator.intel_confidence >= 0.50:
                        self.indicator.confidence_level = 1
                    else:
                        self.indicator.confidence_level = "-"
                else:
                    self.indicator.confidence_level = "-"
        else:
            self.indicator.confidence_level = "-"
            self.indicator.intel_feed = "-"
            self.indicator.intel_confidence = "-"
            self.indicator.e_list_entry = False

        if self.indicator.has_vt_data:
            if self.indicator.days_since_creation > TicketResolver.DAYS_SINCE_CREATION:
                self.indicator.domain_age = "old"
            else:
                self.indicator.domain_age = "new"
        else:
            self.indicator.domain_age = "new"

    def match_rule(self):
        if self.indicator.subdomain_only is False:
            if self.indicator.e_list_entry is False:
                self.logger.info(
                    f"Matching {self.indicator.fqdn} data against rule set"
                )
                group = self.rules.get(self.indicator.ticket.queue)
                if group:
                    type_match = group.get(self.indicator.ticket.ticket_type)
                    if type_match:
                        is_in_intel = type_match.get(self.indicator.is_in_intel)
                        is_filtered = is_in_intel.get(self.indicator.is_filtered)
                        if is_filtered:
                            category_strength = is_filtered.get(
                                self.indicator.intel_category_strength,
                                is_filtered.get("-"),
                            )
                            if category_strength:
                                age = category_strength.get(
                                    self.indicator.domain_age,
                                    category_strength.get("-"),
                                )
                                if age:
                                    if self.indicator.vt_indications != "-":
                                        age.pop("-", "")
                                        min_vt_indications = {}
                                        max_vt_indications = {}
                                        for key, item_value in age.items():
                                            if (
                                                int(key)
                                                <= self.indicator.vt_indications
                                            ):
                                                new_values = {
                                                    k: value
                                                    for k, value in item_value.items()
                                                }
                                                min_vt_indications = merge_dicts(
                                                    min_vt_indications,
                                                    new_values,
                                                )

                                        for (
                                            key,
                                            item_value,
                                        ) in min_vt_indications.items():
                                            if (
                                                int(key)
                                                >= self.indicator.vt_indications
                                            ):
                                                new_values = {
                                                    key: value
                                                    for key, value in item_value.items()
                                                }
                                                max_vt_indications = merge_dicts(
                                                    max_vt_indications,
                                                    new_values,
                                                )
                                    else:
                                        min_vt_indications = age.get(
                                            self.indicator.vt_indications
                                        )
                                        max_vt_indications = min_vt_indications.get(
                                            self.indicator.vt_indications
                                        )

                                    if self.indicator.confidence_level != "-":
                                        max_vt_indications.pop("-", "")
                                        min_confidence = {}
                                        match = {}
                                        for (
                                            key,
                                            item_value,
                                        ) in max_vt_indications.items():
                                            if (
                                                int(key)
                                                <= self.indicator.confidence_level
                                            ):
                                                new_values = {
                                                    key: value
                                                    for key, value in item_value.items()
                                                }
                                                min_confidence = merge_dicts(
                                                    min_confidence,
                                                    new_values,
                                                )

                                        for (
                                            key,
                                            item_value,
                                        ) in min_confidence.items():
                                            if (
                                                int(key)
                                                >= self.indicator.confidence_level
                                            ):
                                                new_values = {
                                                    key: value
                                                    for key, value in item_value.items()
                                                }
                                                match.update(new_values)
                                    else:
                                        min_confidence = max_vt_indications.get(
                                            self.indicator.confidence_level
                                        )
                                        match = min_confidence.get(
                                            self.indicator.confidence_level
                                        )

                                    self.indicator.indicator_resolution = match[
                                        "verdict"
                                    ]
                                    response = match["response"].replace("\\n", "\n")
                                    self.indicator.rule_response = response
                                else:
                                    self.logger.info(
                                        f"Error: No 'age' Value to Match Rule Set. age: {self.indicator.domain_age}"
                                    )
                                    self.indicator.indicator_resolution = "In Progress"
                                    self.indicator.rule_response = "No Rule Match"
                            else:
                                self.logger.info(
                                    f"Error: No 'category_strength' Value to Match Rule Set. category_strength: {self.indicator.category_strength}"
                                )
                                self.indicator.indicator_resolution = "In Progress"
                                self.indicator.rule_response = "No Rule Match"
                        else:
                            self.logger.info(
                                f"Error: No 'is_filtered' Value to Match Rule Set. is_filtered: {self.indicator.is_filtered}"
                            )
                            self.indicator.indicator_resolution = "In Progress"
                            self.indicator.rule_response = "No Rule Match"
                    else:
                        self.logger.info(
                            f"Error: No Type Match in Rule Set. Type: {self.indicator.ticket_type}"
                        )
                        self.indicator.indicator_resolution = "In Progress"
                        self.indicator.rule_response = "No Rule Match"
                else:
                    self.logger.info(
                        f"Error: No Queue Match in Rule Set. Queue: {self.indicator.queue}"
                    )
                    self.indicator.indicator_resolution = "In Progress"
                    self.indicator.rule_response = "No Rule Match"
            else:
                self.indicator.indicator_resolution = "In Progress"
                self.indicator.rule_response = (
                    f"FQDN in exact match lists with {self.indicator.url_count} paths"
                )
        else:
            self.logger.info(
                f"{self.indicator.fqdn} only has {self.indicator.subdomain_count} sudomains in intel"
            )
            self.indicator.indicator_resolution = "In Progress"
            self.indicator.rule_response = f"FQDN not directly in the intel. FQDN has {self.indicator.subdomain_count} subdomains in the intel"

        if (
            int(self.indicator.subdomain_count) > 3
            and self.indicator.indicator_resolution == "Allow"
        ):
            self.indicator.indicator_resolution = "In Progress"
            self.indicator.rule_response = f"FQDN has {self.indicator.subdomain_count} subdomains in the intel and must be analysed manually."


def merge_dicts(dict1, dict2):
    for key, value in dict2.items():
        if key in dict1:
            if isinstance(dict1[key], dict) and isinstance(value, dict):
                merge_dicts(dict1[key], value)
            else:
                dict1[key] += value
        else:
            dict1[key] = value
    return dict1
