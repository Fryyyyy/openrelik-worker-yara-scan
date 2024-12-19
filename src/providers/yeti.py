import os

from yeti.api import YetiApi

from .interface import IntelProvider


class YetiIntelProvider(IntelProvider):
    """Intel provider for the Yeti platform.

    Attrs:
        yeti_client: Yeti API client.
    """

    def __init__(self):
        endpoint = os.environ.get("YETI_ENDPOINT")
        api_key = os.environ.get("YETI_API_KEY")

        if not endpoint or not api_key:
            raise RuntimeError("Yeti API endpoint and key are required")

        self.yeti_client = YetiApi(endpoint)
        self.yeti_client.auth_api_key(api_key)

    def get_yara_rules(self, name_filter: str) -> str:
        """Get all YARA rules from the Yeti platform.

        Args:
            name_filter: Filter for Yara rule names.
        """
        indicators = self.yeti_client.search_indicators(
            name=name_filter, indicator_type="yara"
        )
        all_patterns = ""
        for indicator in indicators:
            all_patterns += indicator["pattern"] + "\n\n"
        return all_patterns
