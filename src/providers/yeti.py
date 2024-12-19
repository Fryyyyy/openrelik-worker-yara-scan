import os

from yeti.api import YetiApi

from .interface import IntelProvider


class YetiIntelProvider(IntelProvider):
    def __init__(self):
        endpoint = os.environ.get("YETI_ENDPOINT")
        api_key = os.environ.get("YETI_API_KEY")

        if not endpoint or not api_key:
            raise RuntimeError("Yeti API endpoint and key are required")

        self.yeti_client = YetiApi(endpoint)
        self.yeti_client.auth_api_key(api_key)

    def get_yara_rules(self) -> str:
        indicators = self.yeti_client.search_indicators(indicator_type="yara")
        all_patterns = ""
        for i in indicators:
            all_patterns += i["pattern"] + "\n\n"
        return all_patterns
