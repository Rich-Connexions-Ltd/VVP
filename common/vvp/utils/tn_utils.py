"""Telephone Number Utilities.

Provides:
- E.164 format validation
- Wildcard expansion
- Range parsing (hyphenated and dict formats)
- Subset validation for TNAlloc credential chains

This module is shared between verifier and issuer services.
"""

import re
from dataclasses import dataclass
from typing import List, Union


class TNParseError(Exception):
    """Invalid telephone number format."""
    pass


@dataclass
class TNRange:
    """Represents a telephone number range.

    Phone numbers are stored as integers (E.164 without the '+' prefix).
    A single number has start == end.
    """
    start: int  # E.164 as integer (e.g., 15551234567)
    end: int    # E.164 as integer

    def contains(self, number: int) -> bool:
        """Check if a number is within this range."""
        return self.start <= number <= self.end

    def is_subset_of(self, other: 'TNRange') -> bool:
        """Check if this range is entirely contained within another range."""
        return other.start <= self.start and self.end <= other.end

    def __repr__(self) -> str:
        if self.start == self.end:
            return f"TNRange(+{self.start})"
        return f"TNRange(+{self.start} to +{self.end})"


# E.164 validation regex: + followed by 1-15 digits
# Per ITU-T E.164, max length is 15 digits (excluding the '+')
E164_PATTERN = re.compile(r'^\+[1-9]\d{0,14}$')
E164_WILDCARD_PATTERN = re.compile(r'^\+[1-9]\d*\*$')


def validate_e164(tn: str) -> None:
    """Validate E.164 format strictly.

    Args:
        tn: The telephone number string to validate.

    Raises:
        TNParseError: If format is invalid.
    """
    if not tn:
        raise TNParseError("Empty telephone number")

    if not tn.startswith('+'):
        raise TNParseError(f"E.164 must start with '+': {tn}")

    if not E164_PATTERN.match(tn) and not E164_WILDCARD_PATTERN.match(tn):
        raise TNParseError(f"Invalid E.164 format: {tn}")


def parse_tn_allocation(tn_data: Union[str, list, dict]) -> List[TNRange]:
    """Parse TN allocation into normalized ranges.

    Supports multiple input formats:
    - Single number: "+15551234567"
    - Wildcard: "+1555*" (matches +1555000... to +1555999...)
    - Hyphenated range: "+15550000000-+15559999999"
    - List: ["+15551234567", "+15559876543"]
    - Dict range: {"start": "+15550000000", "end": "+15559999999"}

    Args:
        tn_data: The TN allocation data in any supported format.

    Returns:
        List of TNRange objects representing the allocation.

    Raises:
        TNParseError: On invalid E.164 format or malformed input.
    """
    if tn_data is None:
        raise TNParseError("TN allocation data is None")

    if isinstance(tn_data, str):
        # Check for hyphenated range format: "+1555...-+1555..."
        if '-+' in tn_data:
            return [_parse_hyphenated_range(tn_data)]
        return [_parse_single_tn(tn_data)]

    elif isinstance(tn_data, list):
        if not tn_data:
            raise TNParseError("Empty TN allocation list")
        ranges = []
        for tn in tn_data:
            if isinstance(tn, str):
                if '-+' in tn:
                    ranges.append(_parse_hyphenated_range(tn))
                else:
                    ranges.append(_parse_single_tn(tn))
            elif isinstance(tn, dict):
                ranges.extend(parse_tn_allocation(tn))
            else:
                raise TNParseError(f"Invalid TN allocation list item type: {type(tn)}")
        return ranges

    elif isinstance(tn_data, dict):
        # Handle {"start": "+1555...", "end": "+1555..."} format
        if "start" in tn_data and "end" in tn_data:
            start_tn = str(tn_data["start"])
            end_tn = str(tn_data["end"])
            validate_e164(start_tn)
            validate_e164(end_tn)
            start_int = _e164_to_int(start_tn)
            end_int = _e164_to_int(end_tn)
            if start_int > end_int:
                raise TNParseError(
                    f"Range start {start_tn} is greater than end {end_tn}"
                )
            return [TNRange(start=start_int, end=end_int)]

        # Handle {"tn": "..."} or {"phone": "..."} nested format
        for key in ("tn", "phone", "allocation", "number"):
            if key in tn_data:
                return parse_tn_allocation(tn_data[key])

        raise TNParseError(f"Invalid TN allocation dict format: {tn_data}")

    raise TNParseError(f"Unsupported TN allocation type: {type(tn_data)}")


def _parse_hyphenated_range(tn: str) -> TNRange:
    """Parse hyphenated range like '+15550000000-+15559999999'.

    Args:
        tn: The hyphenated range string.

    Returns:
        TNRange representing the range.

    Raises:
        TNParseError: If format is invalid or start > end.
    """
    parts = tn.split('-+')
    if len(parts) != 2:
        raise TNParseError(f"Invalid hyphenated range format: {tn}")

    start_tn = parts[0].strip()
    end_tn = '+' + parts[1].strip()

    validate_e164(start_tn)
    validate_e164(end_tn)

    start_int = _e164_to_int(start_tn)
    end_int = _e164_to_int(end_tn)

    if start_int > end_int:
        raise TNParseError(f"Range start {start_tn} is greater than end {end_tn}")

    return TNRange(start=start_int, end=end_int)


def _parse_single_tn(tn: str) -> TNRange:
    """Parse single TN or wildcard to range.

    Args:
        tn: A single phone number or wildcard pattern.

    Returns:
        TNRange representing the number or wildcard expansion.

    Raises:
        TNParseError: If format is invalid.
    """
    tn = tn.strip()
    validate_e164(tn)

    if tn.endswith('*'):
        # Wildcard: "+1555*" -> range covering all numbers with that prefix
        # The wildcard expands to cover all possible suffixes up to E.164 max length
        prefix = tn[:-1]
        prefix_int = _e164_to_int(prefix)

        # Calculate how many digits can follow the prefix
        # E.164 max is 15 digits, prefix already has len(prefix)-1 digits (excluding '+')
        prefix_digits = len(prefix) - 1  # -1 for the '+'
        remaining_digits = 15 - prefix_digits

        if remaining_digits <= 0:
            # Prefix is already at max length, treat as single number
            return TNRange(start=prefix_int, end=prefix_int)

        # Expand wildcard: prefix followed by 0s to prefix followed by 9s
        # For "+1555*" with prefix_int=1555:
        #   start = 1555 * 10^remaining = 15550000000000 (if remaining=10)
        #   end = start + 10^remaining - 1 = 15559999999999
        multiplier = 10 ** remaining_digits
        start = prefix_int * multiplier
        end = start + multiplier - 1

        return TNRange(start=start, end=end)
    else:
        # Single number
        num = _e164_to_int(tn)
        return TNRange(start=num, end=num)


def _e164_to_int(tn: str) -> int:
    """Convert E.164 string to integer (strips '+').

    Args:
        tn: E.164 format phone number (e.g., "+15551234567").

    Returns:
        Integer representation (e.g., 15551234567).
    """
    return int(tn.replace('+', ''))


def is_subset(child_ranges: List[TNRange], parent_ranges: List[TNRange]) -> bool:
    """Check if all child ranges are covered by parent ranges.

    A TNAlloc credential's phone number allocation must be a subset
    of its parent TNAlloc's allocation.

    Args:
        child_ranges: The child allocation ranges to check.
        parent_ranges: The parent allocation ranges that must cover child.

    Returns:
        True if every child range is entirely contained within at least
        one parent range.
    """
    if not child_ranges:
        return True  # Empty child is always subset

    if not parent_ranges:
        return False  # Non-empty child cannot be subset of empty parent

    for child in child_ranges:
        covered = any(child.is_subset_of(parent) for parent in parent_ranges)
        if not covered:
            return False
    return True


def find_uncovered_ranges(
    child_ranges: List[TNRange],
    parent_ranges: List[TNRange]
) -> List[TNRange]:
    """Find child ranges not covered by parent ranges.

    Useful for error messages showing which allocations are invalid.

    Args:
        child_ranges: The child allocation ranges.
        parent_ranges: The parent allocation ranges.

    Returns:
        List of child ranges that are not covered by any parent range.
    """
    uncovered = []
    for child in child_ranges:
        if not any(child.is_subset_of(parent) for parent in parent_ranges):
            uncovered.append(child)
    return uncovered
