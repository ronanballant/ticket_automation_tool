import csv
import os

from config import (etp_automation_data_location, logger, sps_automation_data_location)


class AutomationLogger:
    def __init__(self, entities, responder, start, runtime) -> None:
        self.entities = entities
        self.responder = responder
        self.sps_data_file = sps_automation_data_location
        self.etp_data_file = etp_automation_data_location
        self.start_time = start
        self.runtime = str(runtime)
        self.get_ticket_resolutions()

    def get_ticket_resolutions(self):
        for entity in self.entities:
            entity.ticket_is_resolved = False
            if entity.ticket_id in self.responder.resolved_tickets:
                entity.ticket_is_resolved = True

    def write_sps_data(self):
        data_file = self.sps_data_file
        if not os.path.exists(data_file):
            with open(data_file, "w") as file:
                writer = csv.writer(file)
                writer.writerow(
                    [
                        "ts",
                        "ticket_id",
                        "ticket_type",
                        "ticket_resolved",
                        "domain",
                        "domain_resolved",
                        "malicious_count",
                        "subdomain_count",
                        "last_seen",
                        "categories",
                        "intel_feed",
                        "intel_source",
                        "intel_confidence",
                        "resolution",
                        "source_response",
                        "response",
                        "runtime",
                    ]
                )

        try:
            with open(data_file, "a+") as file:
                writer = csv.writer(file)
                for entity in self.entities:
                    writer.writerow(
                        [
                            self.start_time,
                            entity.ticket_id,
                            entity.ticket_type,
                            entity.ticket_is_resolved,
                            entity.entity,
                            entity.is_resolved,
                            entity.positives,
                            entity.subdomain_count,
                            entity.last_seen,
                            entity.categories,
                            entity.intel_feed,
                            entity.intel_source,
                            entity.intel_confidence,
                            entity.resolution,
                            entity.source_response,
                            entity.response,
                            self.runtime
                        ]
                    )
            logger.info(f"Saved automation data to {data_file}")
        except Exception as e:
            logger.error(f"Error saving automation data to {data_file} - Error: {e}")

    def write_etp_data(self):
        data_file = self.etp_data_file
        if not os.path.exists(data_file):
            with open(data_file, "w") as file:
                writer = csv.writer(file)
                writer.writerow(
                    [
                        "ts",
                        "ticket_id",
                        "ticket_type",
                        "ticket_resolved",
                        "domain",
                        "domain_resolved",
                        "malicious_count",
                        "subdomain_count",
                        "last_seen",
                        "categories",
                        "intel_feed",
                        "intel_source",
                        "filtered",
                        "threat_id",
                        "list_id",
                        "is_in_intel",
                        "resolution",
                        "source_response",
                        "response",
                        "runtime",
                    ]
                )
        try:
            with open(data_file, "a+") as file:
                writer = csv.writer(file)
                for entity in self.entities:
                    writer.writerow(
                        [
                            self.start_time,
                            entity.ticket_id,
                            entity.ticket_type,
                            entity.ticket_is_resolved,
                            entity.entity,
                            entity.is_resolved,
                            entity.positives,
                            entity.subdomain_count,
                            entity.last_seen,
                            entity.categories,
                            entity.intel_category,
                            entity.intel_source,
                            entity.is_filtered,
                            entity.intel_threat_id,
                            entity.intel_list_id,
                            entity.is_in_intel,
                            entity.resolution,
                            entity.source_response,
                            entity.response,
                            self.runtime
                        ]
                    )
            logger.info(f"Saved automation data to {data_file}")
        except Exception as e:
            logger.error(f"Error saving automation data to {data_file} - Error: {e}")
