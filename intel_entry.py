from config import logger
from typing import List


class IntelEntry:
    all_intel_entries = []

    def __init__(self, indicator, entry, intel_list, operation) -> None:
        self.indicator = indicator
        self.entry = entry
        self.intel_list = intel_list
        self.operation = operation
        self.is_approved = False
        self.whitelist: List[str] = []
        self.whitelist_removal: List[str] = []
        self.blacklist: List[str] = []
        self.manual_blacklist: List[str] = []
        self.approved_intel_change: str = None
        IntelEntry.all_intel_entries.append(self)
        
    def to_dict(self):
        intel_processor_dict = self.__dict__.copy()
        intel_processor_dict.pop("indicator", None)  
        return intel_processor_dict

    @classmethod
    def from_dict(cls, data, indicator):
        keys = [ 
            "indicator",
            "entry",
            "intel_list",
            "operation",
        ]

        intel_entry = cls(
            indicator=indicator,
            entry=data["entry"],
            intel_list=data["intel_list"],
            operation=data["operation"],
        )

        for key, value in data.items():
            if key not in keys:
                setattr(intel_entry, key, value)

        return intel_entry

    def append_to_indicator(self):
        self.indicator.append_intel_entry(self)
    
