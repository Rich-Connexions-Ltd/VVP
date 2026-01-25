"""Tests for telephone number utilities.

Tests E.164 validation, range parsing, and subset checking per VVP §6.3.6.
"""

import pytest

from app.vvp.tn_utils import (
    TNParseError,
    TNRange,
    find_uncovered_ranges,
    is_subset,
    parse_tn_allocation,
    validate_e164,
)


class TestValidateE164:
    """Tests for E.164 format validation."""

    def test_valid_e164_us_number(self):
        """Valid US number passes."""
        validate_e164("+15551234567")  # Should not raise

    def test_valid_e164_international(self):
        """Valid international number passes."""
        validate_e164("+442071234567")  # UK
        validate_e164("+33123456789")   # France
        validate_e164("+81312345678")   # Japan

    def test_valid_e164_short(self):
        """Valid short number (min 1 digit after country code)."""
        validate_e164("+1")  # Minimal valid

    def test_valid_e164_max_length(self):
        """Valid maximum length (15 digits)."""
        validate_e164("+123456789012345")  # 15 digits

    def test_valid_wildcard(self):
        """Wildcard format is valid."""
        validate_e164("+1555*")
        validate_e164("+1*")
        validate_e164("+44207*")

    def test_invalid_missing_plus(self):
        """Missing + prefix is invalid."""
        with pytest.raises(TNParseError, match="must start with"):
            validate_e164("15551234567")

    def test_invalid_starts_with_zero(self):
        """E.164 cannot start with 0 after country code."""
        with pytest.raises(TNParseError, match="Invalid E.164"):
            validate_e164("+0551234567")

    def test_invalid_non_numeric(self):
        """Non-numeric characters are invalid."""
        with pytest.raises(TNParseError, match="Invalid E.164"):
            validate_e164("+1555ABC1234")

    def test_invalid_too_long(self):
        """More than 15 digits is invalid."""
        with pytest.raises(TNParseError, match="Invalid E.164"):
            validate_e164("+1234567890123456")  # 16 digits

    def test_invalid_empty(self):
        """Empty string is invalid."""
        with pytest.raises(TNParseError, match="Empty"):
            validate_e164("")


class TestParseTnAllocation:
    """Tests for TN allocation parsing."""

    def test_single_number(self):
        """Parse single phone number."""
        ranges = parse_tn_allocation("+15551234567")
        assert len(ranges) == 1
        assert ranges[0].start == 15551234567
        assert ranges[0].end == 15551234567

    def test_wildcard_expansion(self):
        """Wildcard expands to range."""
        ranges = parse_tn_allocation("+1555*")
        assert len(ranges) == 1
        # +1555* should expand to cover all numbers starting with 1555
        # With 4 prefix digits, we have 11 remaining digits
        assert ranges[0].start == 1555 * (10 ** 11)
        assert ranges[0].end == 1555 * (10 ** 11) + (10 ** 11) - 1

    def test_hyphenated_range(self):
        """Parse hyphenated range string."""
        ranges = parse_tn_allocation("+15550000000-+15559999999")
        assert len(ranges) == 1
        assert ranges[0].start == 15550000000
        assert ranges[0].end == 15559999999

    def test_hyphenated_range_with_spaces(self):
        """Parse hyphenated range with spaces."""
        ranges = parse_tn_allocation("+15550000000 -+ 15559999999")
        assert len(ranges) == 1
        assert ranges[0].start == 15550000000
        assert ranges[0].end == 15559999999

    def test_list_of_numbers(self):
        """Parse list of numbers."""
        ranges = parse_tn_allocation(["+15551234567", "+15559876543"])
        assert len(ranges) == 2
        assert ranges[0].start == 15551234567
        assert ranges[1].start == 15559876543

    def test_list_with_mixed_formats(self):
        """Parse list with mixed number and range."""
        ranges = parse_tn_allocation(["+15551234567", "+15560000000-+15569999999"])
        assert len(ranges) == 2
        assert ranges[0].start == 15551234567
        assert ranges[0].end == 15551234567
        assert ranges[1].start == 15560000000
        assert ranges[1].end == 15569999999

    def test_dict_range(self):
        """Parse dict with start/end keys."""
        ranges = parse_tn_allocation({"start": "+15550000000", "end": "+15559999999"})
        assert len(ranges) == 1
        assert ranges[0].start == 15550000000
        assert ranges[0].end == 15559999999

    def test_dict_nested_tn(self):
        """Parse dict with nested 'tn' key."""
        ranges = parse_tn_allocation({"tn": "+15551234567"})
        assert len(ranges) == 1
        assert ranges[0].start == 15551234567

    def test_invalid_hyphenated_start_gt_end(self):
        """Hyphenated range with start > end is invalid."""
        with pytest.raises(TNParseError, match="greater than end"):
            parse_tn_allocation("+15559999999-+15550000000")

    def test_invalid_dict_start_gt_end(self):
        """Dict range with start > end is invalid."""
        with pytest.raises(TNParseError, match="greater than end"):
            parse_tn_allocation({"start": "+15559999999", "end": "+15550000000"})

    def test_invalid_empty_list(self):
        """Empty list is invalid."""
        with pytest.raises(TNParseError, match="Empty"):
            parse_tn_allocation([])

    def test_invalid_none(self):
        """None is invalid."""
        with pytest.raises(TNParseError, match="None"):
            parse_tn_allocation(None)

    def test_invalid_unsupported_type(self):
        """Unsupported type raises error."""
        with pytest.raises(TNParseError, match="Unsupported"):
            parse_tn_allocation(12345)  # type: ignore


class TestTNRange:
    """Tests for TNRange operations."""

    def test_contains_single_number(self):
        """Single number range contains only that number."""
        r = TNRange(start=15551234567, end=15551234567)
        assert r.contains(15551234567)
        assert not r.contains(15551234568)

    def test_contains_range(self):
        """Range contains numbers within bounds."""
        r = TNRange(start=15550000000, end=15559999999)
        assert r.contains(15550000000)  # Start
        assert r.contains(15559999999)  # End
        assert r.contains(15555555555)  # Middle
        assert not r.contains(15549999999)  # Before
        assert not r.contains(15560000000)  # After

    def test_is_subset_of_identical(self):
        """Range is subset of itself."""
        r = TNRange(start=15550000000, end=15559999999)
        assert r.is_subset_of(r)

    def test_is_subset_of_larger(self):
        """Smaller range is subset of larger."""
        child = TNRange(start=15551000000, end=15552000000)
        parent = TNRange(start=15550000000, end=15559999999)
        assert child.is_subset_of(parent)

    def test_is_not_subset_start_before(self):
        """Range starting before parent is not subset."""
        child = TNRange(start=15549000000, end=15555000000)
        parent = TNRange(start=15550000000, end=15559999999)
        assert not child.is_subset_of(parent)

    def test_is_not_subset_end_after(self):
        """Range ending after parent is not subset."""
        child = TNRange(start=15555000000, end=15560000000)
        parent = TNRange(start=15550000000, end=15559999999)
        assert not child.is_subset_of(parent)

    def test_repr_single(self):
        """String representation of single number."""
        r = TNRange(start=15551234567, end=15551234567)
        assert "+15551234567" in repr(r)

    def test_repr_range(self):
        """String representation of range."""
        r = TNRange(start=15550000000, end=15559999999)
        assert "+15550000000" in repr(r)
        assert "+15559999999" in repr(r)


class TestIsSubset:
    """Tests for subset validation."""

    def test_single_number_in_range(self):
        """Single number within parent range."""
        child = [TNRange(start=15551234567, end=15551234567)]
        parent = [TNRange(start=15550000000, end=15559999999)]
        assert is_subset(child, parent)

    def test_single_number_outside_range(self):
        """Single number outside parent range."""
        child = [TNRange(start=15561234567, end=15561234567)]
        parent = [TNRange(start=15550000000, end=15559999999)]
        assert not is_subset(child, parent)

    def test_wildcard_subset(self):
        """Wildcard subset of larger wildcard."""
        # +1555* is subset of +155*
        child = parse_tn_allocation("+1555*")
        parent = parse_tn_allocation("+155*")
        assert is_subset(child, parent)

    def test_wildcard_not_subset(self):
        """Wildcard not subset of smaller wildcard."""
        # +155* is NOT subset of +1555*
        child = parse_tn_allocation("+155*")
        parent = parse_tn_allocation("+1555*")
        assert not is_subset(child, parent)

    def test_multiple_child_ranges_all_covered(self):
        """Multiple child ranges all within parent."""
        child = [
            TNRange(start=15551234567, end=15551234567),
            TNRange(start=15552345678, end=15552345678),
        ]
        parent = [TNRange(start=15550000000, end=15559999999)]
        assert is_subset(child, parent)

    def test_multiple_child_ranges_one_uncovered(self):
        """Multiple child ranges with one outside parent."""
        child = [
            TNRange(start=15551234567, end=15551234567),
            TNRange(start=15562345678, end=15562345678),  # Outside
        ]
        parent = [TNRange(start=15550000000, end=15559999999)]
        assert not is_subset(child, parent)

    def test_multiple_parent_ranges(self):
        """Child covered by one of multiple parent ranges."""
        child = [TNRange(start=15571234567, end=15571234567)]
        parent = [
            TNRange(start=15550000000, end=15559999999),
            TNRange(start=15570000000, end=15579999999),
        ]
        assert is_subset(child, parent)

    def test_empty_child_always_subset(self):
        """Empty child is always subset."""
        child: list = []
        parent = [TNRange(start=15550000000, end=15559999999)]
        assert is_subset(child, parent)

    def test_non_empty_child_not_subset_of_empty_parent(self):
        """Non-empty child cannot be subset of empty parent."""
        child = [TNRange(start=15551234567, end=15551234567)]
        parent: list = []
        assert not is_subset(child, parent)


class TestFindUncoveredRanges:
    """Tests for finding uncovered ranges."""

    def test_all_covered(self):
        """All ranges covered returns empty list."""
        child = [TNRange(start=15551234567, end=15551234567)]
        parent = [TNRange(start=15550000000, end=15559999999)]
        assert find_uncovered_ranges(child, parent) == []

    def test_one_uncovered(self):
        """Returns uncovered range."""
        uncovered_range = TNRange(start=15562345678, end=15562345678)
        child = [
            TNRange(start=15551234567, end=15551234567),
            uncovered_range,
        ]
        parent = [TNRange(start=15550000000, end=15559999999)]
        result = find_uncovered_ranges(child, parent)
        assert len(result) == 1
        assert result[0] == uncovered_range

    def test_all_uncovered(self):
        """Returns all uncovered ranges."""
        child = [
            TNRange(start=15611234567, end=15611234567),
            TNRange(start=15622345678, end=15622345678),
        ]
        parent = [TNRange(start=15550000000, end=15559999999)]
        result = find_uncovered_ranges(child, parent)
        assert len(result) == 2
