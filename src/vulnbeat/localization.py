from dataclasses import dataclass


@dataclass(frozen=True)
class LocalizedText:
    values: dict[str, str]

    def get(self, lang: str, fallback_lang: str = "en") -> str | None:
        return self.values.get(lang) or self.values.get(fallback_lang)