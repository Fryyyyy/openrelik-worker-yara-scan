from abc import ABC, abstractmethod


class IntelProvider(ABC):
    @abstractmethod
    def get_yara_rules(self):
        """
        Gets Yara rules from the intelligence provider.

        Returns:
            A string containing all Yara rules.
        """
        pass
