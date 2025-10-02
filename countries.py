# countries.py
"""Shared list of European countries used for validation.

This keeps the backend validation logic in sync with the frontend country
selector. The list intentionally contains ISO-3166 alpha-2 country codes and
their human-readable names so we can extend the payload down the line if
needed (e.g. exposing names/flags over the API).
"""

from __future__ import annotations

EUROPEAN_COUNTRIES: dict[str, str] = {
    "AL": "Albania",
    "AD": "Andorra",
    "AM": "Armenia",
    "AT": "Austria",
    "AZ": "Azerbaijan",
    "BA": "Bosnia and Herzegovina",
    "BE": "Belgium",
    "BG": "Bulgaria",
    "BY": "Belarus",
    "CH": "Switzerland",
    "CY": "Cyprus",
    "CZ": "Czech Republic",
    "DE": "Germany",
    "DK": "Denmark",
    "EE": "Estonia",
    "ES": "Spain",
    "FI": "Finland",
    "FR": "France",
    "GB": "United Kingdom",
    "GE": "Georgia",
    "GR": "Greece",
    "HR": "Croatia",
    "HU": "Hungary",
    "IE": "Ireland",
    "IS": "Iceland",
    "IT": "Italy",
    "LI": "Liechtenstein",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "LV": "Latvia",
    "MC": "Monaco",
    "MD": "Moldova",
    "ME": "Montenegro",
    "MK": "North Macedonia",
    "MT": "Malta",
    "NL": "Netherlands",
    "NO": "Norway",
    "PL": "Poland",
    "PT": "Portugal",
    "RO": "Romania",
    "RS": "Serbia",
    "RU": "Russia",
    "SE": "Sweden",
    "SI": "Slovenia",
    "SK": "Slovakia",
    "SM": "San Marino",
    "TR": "Turkey",
    "UA": "Ukraine",
    "VA": "Vatican City",
    "XK": "Kosovo",
}

EUROPEAN_COUNTRY_CODES: set[str] = set(EUROPEAN_COUNTRIES.keys())


def is_european_country(code: str | None) -> bool:
    """Return True if *code* is a recognised ISO-2 code for Europe.

    The check is case-insensitive and gracefully handles ``None`` inputs.
    """

    if not code:
        return False
    return code.strip().upper() in EUROPEAN_COUNTRY_CODES

