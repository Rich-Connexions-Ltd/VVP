"""E.164 and ISO 3166-1 country code utilities.

This module provides mappings and utilities for working with:
- E.164 telephone country codes (1-3 digit prefixes)
- ISO 3166-1 alpha-3 country codes (3-letter codes)

Used by vetter constraint validation to:
- Extract country codes from E.164 telephone numbers
- Map between E.164 and ISO 3166-1 formats
- Validate jurisdiction targets
"""

import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

# E.164 country calling codes mapped to ISO 3166-1 alpha-3
# This covers the most common codes; additional codes can be added as needed
E164_COUNTRY_CODES: dict[str, list[str]] = {
    # 1-digit codes
    "1": ["USA", "CAN"],  # North American Numbering Plan (shared)
    "7": ["RUS", "KAZ"],  # Russia and Kazakhstan (shared)
    # 2-digit codes
    "20": ["EGY"],  # Egypt
    "27": ["ZAF"],  # South Africa
    "30": ["GRC"],  # Greece
    "31": ["NLD"],  # Netherlands
    "32": ["BEL"],  # Belgium
    "33": ["FRA"],  # France
    "34": ["ESP"],  # Spain
    "36": ["HUN"],  # Hungary
    "39": ["ITA"],  # Italy
    "40": ["ROU"],  # Romania
    "41": ["CHE"],  # Switzerland
    "43": ["AUT"],  # Austria
    "44": ["GBR"],  # United Kingdom
    "45": ["DNK"],  # Denmark
    "46": ["SWE"],  # Sweden
    "47": ["NOR"],  # Norway
    "48": ["POL"],  # Poland
    "49": ["DEU"],  # Germany
    "51": ["PER"],  # Peru
    "52": ["MEX"],  # Mexico
    "53": ["CUB"],  # Cuba
    "54": ["ARG"],  # Argentina
    "55": ["BRA"],  # Brazil
    "56": ["CHL"],  # Chile
    "57": ["COL"],  # Colombia
    "58": ["VEN"],  # Venezuela
    "60": ["MYS"],  # Malaysia
    "61": ["AUS"],  # Australia
    "62": ["IDN"],  # Indonesia
    "63": ["PHL"],  # Philippines
    "64": ["NZL"],  # New Zealand
    "65": ["SGP"],  # Singapore
    "66": ["THA"],  # Thailand
    "81": ["JPN"],  # Japan
    "82": ["KOR"],  # South Korea
    "84": ["VNM"],  # Vietnam
    "86": ["CHN"],  # China
    "90": ["TUR"],  # Turkey
    "91": ["IND"],  # India
    "92": ["PAK"],  # Pakistan
    "93": ["AFG"],  # Afghanistan
    "94": ["LKA"],  # Sri Lanka
    "95": ["MMR"],  # Myanmar
    "98": ["IRN"],  # Iran
    # 3-digit codes
    "211": ["SSD"],  # South Sudan
    "212": ["MAR"],  # Morocco
    "213": ["DZA"],  # Algeria
    "216": ["TUN"],  # Tunisia
    "218": ["LBY"],  # Libya
    "220": ["GMB"],  # Gambia
    "221": ["SEN"],  # Senegal
    "222": ["MRT"],  # Mauritania
    "223": ["MLI"],  # Mali
    "224": ["GIN"],  # Guinea
    "225": ["CIV"],  # Ivory Coast
    "226": ["BFA"],  # Burkina Faso
    "227": ["NER"],  # Niger
    "228": ["TGO"],  # Togo
    "229": ["BEN"],  # Benin
    "230": ["MUS"],  # Mauritius
    "231": ["LBR"],  # Liberia
    "232": ["SLE"],  # Sierra Leone
    "233": ["GHA"],  # Ghana
    "234": ["NGA"],  # Nigeria
    "235": ["TCD"],  # Chad
    "236": ["CAF"],  # Central African Republic
    "237": ["CMR"],  # Cameroon
    "238": ["CPV"],  # Cape Verde
    "239": ["STP"],  # Sao Tome and Principe
    "240": ["GNQ"],  # Equatorial Guinea
    "241": ["GAB"],  # Gabon
    "242": ["COG"],  # Republic of Congo
    "243": ["COD"],  # Democratic Republic of Congo
    "244": ["AGO"],  # Angola
    "245": ["GNB"],  # Guinea-Bissau
    "246": ["IOT"],  # British Indian Ocean Territory
    "248": ["SYC"],  # Seychelles
    "249": ["SDN"],  # Sudan
    "250": ["RWA"],  # Rwanda
    "251": ["ETH"],  # Ethiopia
    "252": ["SOM"],  # Somalia
    "253": ["DJI"],  # Djibouti
    "254": ["KEN"],  # Kenya
    "255": ["TZA"],  # Tanzania
    "256": ["UGA"],  # Uganda
    "257": ["BDI"],  # Burundi
    "258": ["MOZ"],  # Mozambique
    "260": ["ZMB"],  # Zambia
    "261": ["MDG"],  # Madagascar
    "262": ["REU"],  # Reunion
    "263": ["ZWE"],  # Zimbabwe
    "264": ["NAM"],  # Namibia
    "265": ["MWI"],  # Malawi
    "266": ["LSO"],  # Lesotho
    "267": ["BWA"],  # Botswana
    "268": ["SWZ"],  # Eswatini
    "269": ["COM"],  # Comoros
    "290": ["SHN"],  # Saint Helena
    "291": ["ERI"],  # Eritrea
    "297": ["ABW"],  # Aruba
    "298": ["FRO"],  # Faroe Islands
    "299": ["GRL"],  # Greenland
    "350": ["GIB"],  # Gibraltar
    "351": ["PRT"],  # Portugal
    "352": ["LUX"],  # Luxembourg
    "353": ["IRL"],  # Ireland
    "354": ["ISL"],  # Iceland
    "355": ["ALB"],  # Albania
    "356": ["MLT"],  # Malta
    "357": ["CYP"],  # Cyprus
    "358": ["FIN"],  # Finland
    "359": ["BGR"],  # Bulgaria
    "370": ["LTU"],  # Lithuania
    "371": ["LVA"],  # Latvia
    "372": ["EST"],  # Estonia
    "373": ["MDA"],  # Moldova
    "374": ["ARM"],  # Armenia
    "375": ["BLR"],  # Belarus
    "376": ["AND"],  # Andorra
    "377": ["MCO"],  # Monaco
    "378": ["SMR"],  # San Marino
    "380": ["UKR"],  # Ukraine
    "381": ["SRB"],  # Serbia
    "382": ["MNE"],  # Montenegro
    "383": ["XKX"],  # Kosovo
    "385": ["HRV"],  # Croatia
    "386": ["SVN"],  # Slovenia
    "387": ["BIH"],  # Bosnia and Herzegovina
    "389": ["MKD"],  # North Macedonia
    "420": ["CZE"],  # Czech Republic
    "421": ["SVK"],  # Slovakia
    "423": ["LIE"],  # Liechtenstein
    "500": ["FLK"],  # Falkland Islands
    "501": ["BLZ"],  # Belize
    "502": ["GTM"],  # Guatemala
    "503": ["SLV"],  # El Salvador
    "504": ["HND"],  # Honduras
    "505": ["NIC"],  # Nicaragua
    "506": ["CRI"],  # Costa Rica
    "507": ["PAN"],  # Panama
    "509": ["HTI"],  # Haiti
    "590": ["GLP"],  # Guadeloupe
    "591": ["BOL"],  # Bolivia
    "592": ["GUY"],  # Guyana
    "593": ["ECU"],  # Ecuador
    "594": ["GUF"],  # French Guiana
    "595": ["PRY"],  # Paraguay
    "596": ["MTQ"],  # Martinique
    "597": ["SUR"],  # Suriname
    "598": ["URY"],  # Uruguay
    "599": ["CUW"],  # Curacao
    "670": ["TLS"],  # Timor-Leste
    "672": ["NFK"],  # Norfolk Island
    "673": ["BRN"],  # Brunei
    "674": ["NRU"],  # Nauru
    "675": ["PNG"],  # Papua New Guinea
    "676": ["TON"],  # Tonga
    "677": ["SLB"],  # Solomon Islands
    "678": ["VUT"],  # Vanuatu
    "679": ["FJI"],  # Fiji
    "680": ["PLW"],  # Palau
    "681": ["WLF"],  # Wallis and Futuna
    "682": ["COK"],  # Cook Islands
    "683": ["NIU"],  # Niue
    "685": ["WSM"],  # Samoa
    "686": ["KIR"],  # Kiribati
    "687": ["NCL"],  # New Caledonia
    "688": ["TUV"],  # Tuvalu
    "689": ["PYF"],  # French Polynesia
    "690": ["TKL"],  # Tokelau
    "691": ["FSM"],  # Micronesia
    "692": ["MHL"],  # Marshall Islands
    "850": ["PRK"],  # North Korea
    "852": ["HKG"],  # Hong Kong
    "853": ["MAC"],  # Macau
    "855": ["KHM"],  # Cambodia
    "856": ["LAO"],  # Laos
    "880": ["BGD"],  # Bangladesh
    "886": ["TWN"],  # Taiwan
    "960": ["MDV"],  # Maldives
    "961": ["LBN"],  # Lebanon
    "962": ["JOR"],  # Jordan
    "963": ["SYR"],  # Syria
    "964": ["IRQ"],  # Iraq
    "965": ["KWT"],  # Kuwait
    "966": ["SAU"],  # Saudi Arabia
    "967": ["YEM"],  # Yemen
    "968": ["OMN"],  # Oman
    "970": ["PSE"],  # Palestine
    "971": ["ARE"],  # United Arab Emirates
    "972": ["ISR"],  # Israel
    "973": ["BHR"],  # Bahrain
    "974": ["QAT"],  # Qatar
    "975": ["BTN"],  # Bhutan
    "976": ["MNG"],  # Mongolia
    "977": ["NPL"],  # Nepal
    "992": ["TJK"],  # Tajikistan
    "993": ["TKM"],  # Turkmenistan
    "994": ["AZE"],  # Azerbaijan
    "995": ["GEO"],  # Georgia
    "996": ["KGZ"],  # Kyrgyzstan
    "998": ["UZB"],  # Uzbekistan
}

# ISO 3166-1 alpha-3 codes to country names (subset for reference)
ISO3166_ALPHA3_CODES: dict[str, str] = {
    "AFG": "Afghanistan",
    "ALB": "Albania",
    "ARE": "United Arab Emirates",
    "ARG": "Argentina",
    "AUS": "Australia",
    "AUT": "Austria",
    "BEL": "Belgium",
    "BGD": "Bangladesh",
    "BRA": "Brazil",
    "CAN": "Canada",
    "CHE": "Switzerland",
    "CHN": "China",
    "DEU": "Germany",
    "DNK": "Denmark",
    "EGY": "Egypt",
    "ESP": "Spain",
    "FIN": "Finland",
    "FRA": "France",
    "GBR": "United Kingdom",
    "GRC": "Greece",
    "HKG": "Hong Kong",
    "IDN": "Indonesia",
    "IND": "India",
    "IRL": "Ireland",
    "IRN": "Iran",
    "ISR": "Israel",
    "ITA": "Italy",
    "JPN": "Japan",
    "KEN": "Kenya",
    "KOR": "South Korea",
    "MEX": "Mexico",
    "MYS": "Malaysia",
    "NGA": "Nigeria",
    "NLD": "Netherlands",
    "NOR": "Norway",
    "NZL": "New Zealand",
    "PAK": "Pakistan",
    "PHL": "Philippines",
    "POL": "Poland",
    "PRT": "Portugal",
    "RUS": "Russia",
    "SAU": "Saudi Arabia",
    "SGP": "Singapore",
    "SWE": "Sweden",
    "THA": "Thailand",
    "TUR": "Turkey",
    "TWN": "Taiwan",
    "UKR": "Ukraine",
    "USA": "United States",
    "VNM": "Vietnam",
    "ZAF": "South Africa",
}


def extract_e164_country_code(tn: str) -> str:
    """Extract E.164 country code from telephone number.

    E.164 numbers start with '+' followed by country code (1-3 digits)
    then the subscriber number. This function extracts just the country
    code portion.

    Args:
        tn: E.164 telephone number (e.g., "+447884666200", "+12025551234")

    Returns:
        Country code string (e.g., "44", "1")

    Examples:
        >>> extract_e164_country_code("+447884666200")
        "44"
        >>> extract_e164_country_code("+12025551234")
        "1"
        >>> extract_e164_country_code("+919876543210")
        "91"
    """
    # Remove + prefix and any non-digit characters
    digits = re.sub(r"[^\d]", "", tn)

    if not digits:
        log.warning(f"Cannot extract country code from empty or invalid TN: {tn}")
        return ""

    # Try 3-digit, then 2-digit, then 1-digit codes
    for length in [3, 2, 1]:
        if len(digits) >= length:
            prefix = digits[:length]
            if prefix in E164_COUNTRY_CODES:
                return prefix

    # Default to first digit if no known code matches
    log.warning(f"Unknown E.164 country code for TN: {tn}, using first digit")
    return digits[0] if digits else ""


def e164_to_iso3166(e164_code: str) -> Optional[str]:
    """Convert E.164 country code to ISO 3166-1 alpha-3 code.

    Note: Some E.164 codes map to multiple countries (e.g., "1" for USA/CAN).
    In these cases, returns the first (primary) country.

    Args:
        e164_code: E.164 country code (e.g., "44", "1", "91")

    Returns:
        ISO 3166-1 alpha-3 code or None if not found

    Examples:
        >>> e164_to_iso3166("44")
        "GBR"
        >>> e164_to_iso3166("1")
        "USA"  # Primary country for NANP
        >>> e164_to_iso3166("999")
        None
    """
    countries = E164_COUNTRY_CODES.get(e164_code)
    if countries:
        return countries[0]
    return None


def normalize_country_code(code: str) -> str:
    """Normalize country code to uppercase ISO 3166-1 alpha-3 format.

    Handles both alpha-2 (2-letter) and alpha-3 (3-letter) input,
    converting alpha-2 to alpha-3 where known.

    Args:
        code: Country code (e.g., "gbr", "GBR", "GB", "uk")

    Returns:
        Uppercase ISO 3166-1 alpha-3 code

    Examples:
        >>> normalize_country_code("gbr")
        "GBR"
        >>> normalize_country_code("GB")
        "GBR"
    """
    code = code.strip().upper()

    # Already alpha-3?
    if len(code) == 3:
        return code

    # Common alpha-2 to alpha-3 mappings
    alpha2_to_alpha3 = {
        "AF": "AFG",
        "AL": "ALB",
        "AE": "ARE",
        "AR": "ARG",
        "AU": "AUS",
        "AT": "AUT",
        "BE": "BEL",
        "BD": "BGD",
        "BR": "BRA",
        "CA": "CAN",
        "CH": "CHE",
        "CN": "CHN",
        "DE": "DEU",
        "DK": "DNK",
        "EG": "EGY",
        "ES": "ESP",
        "FI": "FIN",
        "FR": "FRA",
        "GB": "GBR",
        "GR": "GRC",
        "HK": "HKG",
        "ID": "IDN",
        "IE": "IRL",
        "IL": "ISR",
        "IN": "IND",
        "IR": "IRN",
        "IT": "ITA",
        "JP": "JPN",
        "KE": "KEN",
        "KR": "KOR",
        "MX": "MEX",
        "MY": "MYS",
        "NG": "NGA",
        "NL": "NLD",
        "NO": "NOR",
        "NZ": "NZL",
        "PH": "PHL",
        "PK": "PAK",
        "PL": "POL",
        "PT": "PRT",
        "RU": "RUS",
        "SA": "SAU",
        "SG": "SGP",
        "SE": "SWE",
        "TH": "THA",
        "TR": "TUR",
        "TW": "TWN",
        "UA": "UKR",
        "UK": "GBR",  # Common alias
        "US": "USA",
        "VN": "VNM",
        "ZA": "ZAF",
    }

    return alpha2_to_alpha3.get(code, code)


def is_valid_e164_code(code: str) -> bool:
    """Check if a string is a valid E.164 country code.

    Args:
        code: Potential E.164 country code

    Returns:
        True if code is a known E.164 country code
    """
    return code in E164_COUNTRY_CODES


def is_valid_iso3166_alpha3(code: str) -> bool:
    """Check if a string is a valid ISO 3166-1 alpha-3 code.

    Args:
        code: Potential ISO 3166-1 alpha-3 code

    Returns:
        True if code is a known ISO 3166-1 alpha-3 code
    """
    return code.upper() in ISO3166_ALPHA3_CODES
