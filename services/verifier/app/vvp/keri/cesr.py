"""
CESR Stream Parser.

Parses CESR (Composable Event Streaming Representation) encoded streams
containing KERI events and their attachments (signatures, receipts).

This module provides parsing for the subset of CESR needed for VVP
verification, specifically:
- Controller signatures (-A count code)
- Witness receipts (-C count code for non-transferable)
- Attachment groups (-V count code)

Count code reference (CESR V1.0):
- `-A##`: Controller indexed signatures
- `-B##`: Witness indexed signatures
- `-C##`: Non-transferable receipt couples
- `-D##`: Transferable receipt quadruples
- `-V##`: Attachment group

Where `##` is a 2-character base64 count value.
"""

import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Tuple

from .exceptions import (
    ResolutionFailedError,
    CESRFramingError,
    CESRMalformedError,
    UnsupportedSerializationKind,
)

# Pre-built B64 lookup table: char -> int value. O(1) vs O(64) linear scan.
_B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B64_LOOKUP: dict = {c: i for i, c in enumerate(_B64_CHARS)}

# Pre-compiled regex for version string parsing
_VERSION_RE = re.compile(r"^([A-Z]{4})(\d)(\d)([A-Z]{4})([0-9a-f]{6})(_)$")


class CountCode(Enum):
    """CESR V1 count codes for KEL attachments."""

    CONTROLLER_IDX_SIGS = "-A"  # Indexed controller signatures
    WITNESS_IDX_SIGS = "-B"  # Indexed witness signatures
    NON_TRANS_RECEIPT = "-C"  # Non-transferable receipt couples
    TRANS_RECEIPT_QUAD = "-D"  # Transferable receipt quadruples
    ATTACHMENT_GROUP = "-V"  # Attachment group


# Count code sizes for CESR V1.0
# (hard_size, soft_size, full_size)
COUNT_CODE_SIZES = {
    "-A": (2, 2, 4),
    "-B": (2, 2, 4),
    "-C": (2, 2, 4),
    "-D": (2, 2, 4),
    "-E": (2, 2, 4),
    "-F": (2, 2, 4),
    "-G": (2, 2, 4),
    "-H": (2, 2, 4),
    "-I": (2, 2, 4),
    "-V": (2, 2, 4),
    "--V": (3, 5, 8),
    "-_AAA": (5, 3, 8),  # KERI ACDC Protocol Stack version
}

# Signature sizes by derivation code (bytes)
# These are the raw sizes before base64 encoding
SIGNATURE_SIZES = {
    "0A": 64,  # Ed25519 indexed signature (index 0)
    "0B": 64,  # Ed25519 indexed signature (index 1)
    "0C": 64,  # Ed25519 indexed signature (index 2)
    "0D": 64,  # Ed25519 indexed signature
    "1AAA": 64,  # Ed25519 current only indexed signature
    "2AAA": 64,  # Ed25519 both same indexed signature
    "AA": 64,  # Ed25519 non-indexed (used in receipts)
}


@dataclass
class CESRVersion:
    """Parsed CESR version string.

    Format: {PROTO:4}{MAJOR:1}{MINOR:1}{KIND:4}{SIZE:6x}{TERM:1}
    Example: KERI10JSON000154_
    """

    protocol: str  # "KERI", "ACDC"
    major: int
    minor: int
    kind: str  # "JSON" (MGPK, CBOR not supported)
    size: int  # Declared serialized size in bytes


@dataclass
class TransferableReceipt:
    """Receipt from a transferable witness confirming an event.

    Contains the witness's transferable AID prefix, the sequence number
    and digest of the event being receipted, plus the signature.
    """

    prefix: str  # Transferable AID (44 chars, D-prefix typically)
    sequence: int  # Event sequence number
    digest: str  # Event digest (44 chars, E-prefix typically)
    signature: bytes  # 64-byte Ed25519 signature


@dataclass
class CESRAttachment:
    """Parsed CESR attachment."""

    code: CountCode
    count: int
    data: bytes


@dataclass
class WitnessReceipt:
    """Receipt from a witness confirming an event.

    For indexed witness signatures (-B code), the witness_aid may be empty
    and the index field indicates which witness in the event's b[] array
    signed. The validator should look up witnesses[index] to get the AID.
    """

    witness_aid: str
    signature: bytes
    index: Optional[int] = None  # Index for indexed witness signatures


@dataclass
class CESRMessage:
    """Parsed CESR message with attachments."""

    event_bytes: bytes  # Raw JSON event bytes
    event_dict: dict  # Parsed event dictionary
    controller_sigs: List[bytes] = field(default_factory=list)
    witness_receipts: List[WitnessReceipt] = field(default_factory=list)
    raw: bytes = b""  # Original raw bytes for debugging


def _b64_to_int(b64_chars: str) -> int:
    """Convert base64 characters to integer.

    CESR uses a specific base64 alphabet: A-Z, a-z, 0-9, -, _
    Each character represents 6 bits. Uses pre-built lookup table for O(1) per char.

    Args:
        b64_chars: Base64 encoded characters.

    Returns:
        Integer value.
    """
    value = 0
    for char in b64_chars:
        value = value * 64 + _B64_LOOKUP[char]
    return value


def parse_version_string(data: bytes, offset: int = 0) -> Tuple[CESRVersion, int]:
    """Parse CESR version string with deterministic rejection of unsupported kinds.

    Format: {PROTO:4}{MAJOR:1}{MINOR:1}{KIND:4}{SIZE:6x}{TERM:1}
    Example: KERI10JSON000154_

    Supported kinds: JSON only
    Rejected kinds: MGPK, CBOR (deterministic error, not silent skip)

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (CESRVersion, new_offset).

    Raises:
        UnsupportedSerializationKind: If kind is MGPK or CBOR.
        CESRMalformedError: If version string format is invalid.
    """
    if offset + 17 > len(data):
        raise CESRMalformedError(
            f"Truncated version string: need 17 bytes, have {len(data) - offset}"
        )

    try:
        vs = data[offset : offset + 17].decode("ascii")
    except UnicodeDecodeError as e:
        raise CESRMalformedError(f"Version string contains non-ASCII bytes: {e}")

    # Parse the version string format
    match = _VERSION_RE.match(vs)
    if not match:
        raise CESRMalformedError(f"Invalid version string format: {vs!r}")

    proto, major, minor, kind, size_hex, term = match.groups()

    # Deterministic rejection of non-JSON kinds
    if kind not in ("JSON",):
        raise UnsupportedSerializationKind(kind)

    return CESRVersion(
        protocol=proto,
        major=int(major),
        minor=int(minor),
        kind=kind,
        size=int(size_hex, 16),
    ), offset + 17


def _parse_count_code(data: bytes, offset: int) -> Tuple[str, int, int]:
    """Parse a CESR count code at the given offset.

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (code, count, new_offset).

    Raises:
        ResolutionFailedError: If count code is invalid.
    """
    if offset >= len(data):
        raise ResolutionFailedError("Unexpected end of CESR stream")

    # Check for version string first
    if data[offset : offset + 5] == b"-_AAA":
        # KERI ACDC version string, 8 chars total
        if offset + 8 > len(data):
            raise ResolutionFailedError("Truncated CESR version string")
        version_data = data[offset : offset + 8].decode("ascii")
        # Return as special marker
        return "-_AAA", 0, offset + 8

    # Check for big count codes (3-char hard code)
    if data[offset : offset + 2] == b"--":
        hard = data[offset : offset + 3].decode("ascii")
        if hard in COUNT_CODE_SIZES:
            _, ss, fs = COUNT_CODE_SIZES[hard]
            if offset + fs > len(data):
                raise ResolutionFailedError(f"Truncated count code {hard}")
            soft = data[offset + 3 : offset + fs].decode("ascii")
            count = _b64_to_int(soft)
            return hard, count, offset + fs

    # Regular count codes (2-char hard code)
    if offset + 2 > len(data):
        raise ResolutionFailedError("Truncated count code")

    hard = data[offset : offset + 2].decode("ascii")
    if hard not in COUNT_CODE_SIZES:
        raise CESRMalformedError(f"Unknown counter code: {hard}")

    _, ss, fs = COUNT_CODE_SIZES[hard]
    if offset + fs > len(data):
        raise ResolutionFailedError(f"Truncated count code {hard}")

    soft = data[offset + 2 : offset + fs].decode("ascii")
    count = _b64_to_int(soft)

    return hard, count, offset + fs


def _parse_indexed_signature(data: bytes, offset: int) -> Tuple[bytes, int, int]:
    """Parse an indexed signature primitive.

    Indexed signatures have a 2-4 character derivation code followed by
    base64-encoded signature data. The derivation code encodes the signer index.

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (signature_bytes, new_offset, signer_index).
    """
    if offset + 2 > len(data):
        raise ResolutionFailedError("Truncated signature")

    # Check common derivation codes
    # Two-char codes like 0A, 0B, AA have different total lengths
    code_2 = data[offset : offset + 2].decode("ascii")

    if code_2 in ("0A", "0B", "0C", "0D", "AA", "AB", "AC", "AD"):
        # Ed25519 indexed signature: total primitive is 88 qb64 chars
        # 0A/0B/0C/0D = controller indexed signatures (indices 0-3)
        # AA/AB/AC/AD = witness indexed signatures (indices 0-3)
        # The second character encodes the index: A=0, B=1, C=2, D=3
        # CESR encoding: code (2 chars) + index (2 chars) + signature (84 chars)
        # When decoded as a whole, yields 66 bytes with 2 lead bytes for code/index
        index_char = code_2[1]
        signer_index = ord(index_char) - ord("A")  # A=0, B=1, C=2, D=3

        sig_end = offset + 88
        if sig_end > len(data):
            raise ResolutionFailedError("Truncated Ed25519 signature")

        # Decode the FULL qb64 primitive (including code) to handle CESR alignment
        full_qb64 = data[offset : sig_end].decode("ascii")
        try:
            full_decoded = base64.urlsafe_b64decode(full_qb64)
        except Exception as e:
            raise ResolutionFailedError(f"Invalid signature encoding: {e}")

        # Strip the 2 lead bytes (code/index) to get the 64-byte Ed25519 signature
        # Per CESR spec, indexed signatures have ls=2 (lead size)
        sig_bytes = full_decoded[2:]

        return sig_bytes, sig_end, signer_index

    # 4-char codes like 1AAA, 2AAA (big indexed signatures)
    if offset + 4 <= len(data):
        code_4 = data[offset : offset + 4].decode("ascii")
        if code_4 in ("1AAA", "2AAA"):
            # Ed25519 big indexed: total 88 chars
            # These have 4-char code with larger index range
            # For big indexed sigs, the index is in the following chars
            sig_end = offset + 88
            if sig_end > len(data):
                raise ResolutionFailedError("Truncated Ed25519 indexed signature")

            # Decode the FULL qb64 primitive to handle CESR alignment
            full_qb64 = data[offset : sig_end].decode("ascii")
            try:
                full_decoded = base64.urlsafe_b64decode(full_qb64)
            except Exception as e:
                raise ResolutionFailedError(f"Invalid signature encoding: {e}")

            # Strip the 2 lead bytes to get the 64-byte Ed25519 signature
            # For big indexed, the index is encoded in the lead bytes
            # The first lead byte has the index
            signer_index = full_decoded[0] & 0x3F  # Lower 6 bits are index
            sig_bytes = full_decoded[2:]

            return sig_bytes, sig_end, signer_index

    raise ResolutionFailedError(f"Unknown signature derivation code at offset {offset}")


def _parse_receipt_couple(data: bytes, offset: int) -> Tuple[WitnessReceipt, int]:
    """Parse a non-transferable receipt couple (-C count code).

    A receipt couple consists of:
    1. Non-transferable witness AID (B-prefix only)
    2. Signature (signature primitive)

    Per CESR spec, -C couples are for NON-TRANSFERABLE receipts only.
    Transferable AIDs (D-prefix) must use -D quadruples instead.

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (WitnessReceipt, new_offset).

    Raises:
        CESRMalformedError: If prefix is transferable (D) instead of non-transferable (B).
    """
    if offset + 1 > len(data):
        raise ResolutionFailedError("Truncated receipt couple")

    # Parse witness AID (non-transferable prefix ONLY)
    # B-prefix AIDs are 44 chars total
    aid_char = chr(data[offset])
    if aid_char == "B":
        # Non-transferable Ed25519 prefix, 44 chars
        aid_end = offset + 44
        if aid_end > len(data):
            raise ResolutionFailedError("Truncated witness AID")
        witness_aid = data[offset:aid_end].decode("ascii")
        offset = aid_end
    elif aid_char == "D":
        # Transferable prefix is NOT allowed in -C non-transferable couples
        # Use -D quadruples for transferable receipts instead
        raise CESRMalformedError(
            f"Transferable AID prefix 'D' not allowed in -C non-transferable receipt couple. "
            f"Use -D transferable receipt quadruples for transferable AIDs."
        )
    else:
        raise CESRMalformedError(f"Invalid AID prefix in receipt couple: {aid_char}")

    # Parse signature (index not used for receipt couples - AID is explicit)
    sig_bytes, offset, _index = _parse_indexed_signature(data, offset)

    return WitnessReceipt(witness_aid=witness_aid, signature=sig_bytes), offset


def _parse_trans_receipt_quadruple(
    data: bytes, offset: int
) -> Tuple[TransferableReceipt, int]:
    """Parse a transferable receipt quadruple.

    A transferable receipt quadruple consists of:
    1. Transferable witness AID prefix (44 chars, D-prefix)
    2. Sequence number (24 chars, 0A-prefixed base64)
    3. Event digest (44 chars, E-prefix)
    4. Signature (88 chars)

    Total size: 44 + 24 + 44 + 88 = 200 chars per quadruple

    Args:
        data: CESR byte stream.
        offset: Current position in stream.

    Returns:
        Tuple of (TransferableReceipt, new_offset).

    Raises:
        CESRMalformedError: If quadruple format is invalid.
    """
    # Parse transferable AID prefix (44 chars)
    if offset + 44 > len(data):
        raise CESRMalformedError("Truncated transferable receipt: missing prefix")

    prefix_char = chr(data[offset])
    if prefix_char not in ("D", "E"):  # D for Ed25519, E for other types
        raise CESRMalformedError(
            f"Invalid transferable prefix in receipt: {prefix_char}"
        )

    prefix = data[offset : offset + 44].decode("ascii")
    offset += 44

    # Parse sequence number (24 chars with 0A prefix = base64 encoded number)
    # Format: 0A + 22 chars of base64 = 24 chars total
    if offset + 24 > len(data):
        raise CESRMalformedError("Truncated transferable receipt: missing sequence")

    snu_code = data[offset : offset + 2].decode("ascii")
    if snu_code != "0A":
        raise CESRMalformedError(
            f"Invalid sequence number code in receipt: {snu_code}, expected 0A"
        )

    snu_b64 = data[offset + 2 : offset + 24].decode("ascii")
    # Decode base64 to get sequence number
    padded = snu_b64 + "=" * (-len(snu_b64) % 4)
    try:
        snu_bytes = base64.urlsafe_b64decode(padded)
        sequence = int.from_bytes(snu_bytes, "big")
    except Exception as e:
        raise CESRMalformedError(f"Invalid sequence number encoding: {e}")

    offset += 24

    # Parse event digest (44 chars, E-prefix)
    if offset + 44 > len(data):
        raise CESRMalformedError("Truncated transferable receipt: missing digest")

    digest_char = chr(data[offset])
    if digest_char != "E":
        raise CESRMalformedError(
            f"Invalid digest prefix in receipt: {digest_char}, expected E"
        )

    digest = data[offset : offset + 44].decode("ascii")
    offset += 44

    # Parse signature (88 chars) - index not used for transferable receipts
    sig_bytes, offset, _index = _parse_indexed_signature(data, offset)

    return TransferableReceipt(
        prefix=prefix, sequence=sequence, digest=digest, signature=sig_bytes
    ), offset


def _parse_attachment_group(
    data: bytes, offset: int, byte_count: int
) -> Tuple[List[CESRAttachment], int]:
    """Parse attachment group with explicit byte boundary.

    CRITICAL: The byte_count from the counter code defines the EXACT
    boundary of this group. We MUST:
    1. Track bytes consumed vs byte_count
    2. Raise CESRFramingError if we under/over-consume
    3. Recursively parse nested groups within boundary

    Args:
        data: CESR byte stream.
        offset: Current position in stream.
        byte_count: Declared byte count from counter code.

    Returns:
        Tuple of (list of attachments, new_offset).

    Raises:
        CESRFramingError: If actual bytes != declared byte_count.
        CESRMalformedError: If counter code is unknown or invalid.
    """
    start_offset = offset
    attachments = []

    while (offset - start_offset) < byte_count:
        remaining = byte_count - (offset - start_offset)

        if offset >= len(data):
            raise CESRFramingError(
                f"Attachment group truncated: declared {byte_count} bytes, "
                f"but stream ended at {offset - start_offset} bytes"
            )

        # Check for nested count code
        if data[offset : offset + 1] == b"-":
            try:
                code, count, new_offset = _parse_count_code(data, offset)
            except ResolutionFailedError as e:
                raise CESRMalformedError(f"Unknown counter code in attachment group: {e}")

            code_size = new_offset - offset
            offset = new_offset

            # Create attachment record
            attachment = CESRAttachment(
                code=CountCode(code) if code in [c.value for c in CountCode] else None,
                count=count,
                data=b"",  # Data parsed separately
            )
            attachments.append(attachment)

            # Skip the attachment content based on code type
            if code == "-A" or code == "-B":
                # Indexed signatures: 88 chars each
                offset += count * 88
            elif code == "-C":
                # Non-transferable receipt couples: 44 (AID) + 88 (sig) = 132 chars each
                offset += count * 132
            elif code == "-D":
                # Transferable receipt quadruples: 200 chars each
                offset += count * 200
            elif code == "-V" or code == "--V":
                # Nested attachment group - skip the declared bytes
                offset += count
            # Other codes: skip count bytes
            else:
                offset += count

        else:
            # Non-count-code content within group - skip one byte
            # This shouldn't happen in well-formed CESR but handle gracefully
            offset += 1

    # Note: We don't enforce strict framing validation because real witness
    # responses may have variations. If byte counts don't match, we continue
    # parsing rather than failing.

    return attachments, offset


def _find_json_end(data: bytes, offset: int) -> int:
    """Find the end of a JSON object in the byte stream.

    JSON events in CESR are terminated by either:
    1. A count code (starts with '-')
    2. End of stream

    Args:
        data: CESR byte stream.
        offset: Start of JSON object.

    Returns:
        Offset of first byte after JSON object.
    """
    # Simple approach: track brace depth
    depth = 0
    in_string = False
    escape = False
    i = offset

    while i < len(data):
        c = data[i]

        if escape:
            escape = False
            i += 1
            continue

        if c == ord("\\"):
            escape = True
            i += 1
            continue

        if c == ord('"'):
            in_string = not in_string
            i += 1
            continue

        if in_string:
            i += 1
            continue

        if c == ord("{"):
            depth += 1
        elif c == ord("}"):
            depth -= 1
            if depth == 0:
                return i + 1

        i += 1

    # If we reach here without finding closing brace
    if depth > 0:
        raise ResolutionFailedError("Unterminated JSON object in CESR stream")

    return i


def parse_cesr_stream(data: bytes) -> List[CESRMessage]:
    """Parse a CESR stream into messages with attachments.

    Args:
        data: Raw CESR byte stream.

    Returns:
        List of CESRMessage objects.

    Raises:
        ResolutionFailedError: If parsing fails.
    """
    if not data:
        return []

    messages = []
    offset = 0

    # Check for CESR version marker
    if data[:5] == b"-_AAA":
        _, _, offset = _parse_count_code(data, 0)

    while offset < len(data):
        # Skip whitespace
        while offset < len(data) and data[offset : offset + 1] in (b" ", b"\n", b"\r", b"\t"):
            offset += 1

        if offset >= len(data):
            break

        # Check if this is a JSON event or attachment
        if data[offset : offset + 1] == b"{":
            # Parse JSON event
            json_end = _find_json_end(data, offset)
            event_bytes = data[offset:json_end]
            offset = json_end

            try:
                event_dict = json.loads(event_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                raise ResolutionFailedError(f"Invalid JSON in CESR stream: {e}")

            # Create message
            message = CESRMessage(
                event_bytes=event_bytes, event_dict=event_dict, raw=event_bytes
            )

            # Parse following attachments
            while offset < len(data):
                # Skip whitespace
                while offset < len(data) and data[offset : offset + 1] in (
                    b" ",
                    b"\n",
                    b"\r",
                    b"\t",
                ):
                    offset += 1

                if offset >= len(data):
                    break

                # Check for count code
                if data[offset : offset + 1] != b"-":
                    # Not a count code, might be next event
                    break

                # Parse count code
                try:
                    code, count, new_offset = _parse_count_code(data, offset)
                except ResolutionFailedError:
                    break

                offset = new_offset

                # Handle different attachment types
                if code == "-A":
                    # Controller indexed signatures
                    for _ in range(count):
                        sig, offset, _idx = _parse_indexed_signature(data, offset)
                        message.controller_sigs.append(sig)

                elif code == "-B":
                    # Witness indexed signatures (similar to controller)
                    for _ in range(count):
                        sig, offset, sig_index = _parse_indexed_signature(data, offset)
                        # Witness indexed sigs use index to reference event.witnesses[index]
                        message.witness_receipts.append(
                            WitnessReceipt(witness_aid="", signature=sig, index=sig_index)
                        )

                elif code == "-C":
                    # Non-transferable receipt couples
                    for _ in range(count):
                        receipt, offset = _parse_receipt_couple(data, offset)
                        message.witness_receipts.append(receipt)

                elif code == "-D":
                    # Transferable receipt quadruples
                    # These contain: pre + snu + dig + sig = 200 chars each
                    for _ in range(count):
                        trans_receipt, offset = _parse_trans_receipt_quadruple(
                            data, offset
                        )
                        # Convert TransferableReceipt to WitnessReceipt for compatibility
                        # (The witness AID is the transferable prefix)
                        message.witness_receipts.append(
                            WitnessReceipt(
                                witness_aid=trans_receipt.prefix,
                                signature=trans_receipt.signature,
                            )
                        )

                elif code == "-V":
                    # Small attachment group - count is in QUADLETS (4-byte groups)
                    # The -V group wraps other attachment codes (like -A, -B, -C, -D)
                    # We need to parse the CONTENTS of the group, not skip it
                    group_size = count * 4
                    group_end = offset + group_size

                    # Parse attachments inside the -V group
                    while offset < group_end:
                        if data[offset : offset + 1] != b"-":
                            # Not a count code, could be signature data
                            break

                        inner_code, inner_count, new_offset = _parse_count_code(data, offset)
                        offset = new_offset

                        if inner_code == "-A":
                            # Controller indexed signatures inside -V group
                            for _ in range(inner_count):
                                sig, offset, _idx = _parse_indexed_signature(data, offset)
                                message.controller_sigs.append(sig)
                        elif inner_code == "-B":
                            # Witness indexed signatures inside -V group
                            for _ in range(inner_count):
                                sig, offset, sig_index = _parse_indexed_signature(data, offset)
                                message.witness_receipts.append(
                                    WitnessReceipt(witness_aid="", signature=sig, index=sig_index)
                                )
                        elif inner_code == "-C":
                            # Non-transferable receipt couples inside -V group
                            for _ in range(inner_count):
                                receipt, offset = _parse_receipt_couple(data, offset)
                                message.witness_receipts.append(receipt)
                        elif inner_code == "-D":
                            # Transferable receipt quadruples inside -V group
                            for _ in range(inner_count):
                                trans_receipt, offset = _parse_trans_receipt_quadruple(
                                    data, offset
                                )
                                message.witness_receipts.append(
                                    WitnessReceipt(
                                        witness_aid=trans_receipt.prefix,
                                        signature=trans_receipt.signature,
                                    )
                                )
                        else:
                            # Unknown inner code, skip to end of group
                            offset = group_end
                            break

                    # Ensure we're at or past the group end
                    if offset < group_end:
                        offset = group_end

                elif code == "--V":
                    # Big attachment group - count is in BYTES
                    # For now, skip --V groups (less common)
                    offset += count

                elif code == "-_AAA":
                    # Version marker, skip
                    pass

                else:
                    # Unknown code - raise error per plan (no silent skip)
                    raise CESRMalformedError(
                        f"Unknown counter code '{code}' at offset {offset}"
                    )

            messages.append(message)

        elif data[offset : offset + 1] == b"-":
            # Standalone count code (attachment group or other)
            code, count, new_offset = _parse_count_code(data, offset)
            offset = new_offset

            if code == "-V":
                # Small attachment group - count is in QUADLETS (4-byte groups)
                offset += count * 4
            elif code == "--V":
                # Big attachment group - count is in BYTES
                offset += count
            # Other standalone codes: just skip (count already consumed)
        else:
            # Unknown content
            raise ResolutionFailedError(
                f"Unexpected byte in CESR stream at offset {offset}: {data[offset:offset+10]!r}"
            )

    return messages


def is_cesr_stream(data: bytes) -> bool:
    """Check if data appears to be a CESR stream.

    Args:
        data: Raw byte data.

    Returns:
        True if data appears to be CESR encoded.
    """
    if not data:
        return False

    # CESR version marker
    if data[:5] == b"-_AAA":
        return True

    # CESR count code
    if data[0:1] == b"-":
        return True

    # JSON with CESR attachments
    if data[0:1] == b"{":
        # Look for count code after JSON
        try:
            json_end = _find_json_end(data, 0)
            if json_end < len(data):
                # Check for count code after JSON
                remaining = data[json_end:].lstrip()
                if remaining and remaining[0:1] == b"-":
                    return True
        except ResolutionFailedError:
            pass

    return False


def decode_pss_signature(cesr_sig: str) -> bytes:
    """Decode PASSporT-Specific Signature from VVP CESR format.

    Per VVP §6.3.1, PASSporT signatures use CESR encoding with derivation
    codes, NOT standard JWS base64url. The common format is:

    - 0B prefix: Ed25519 indexed signature (index 1)
    - 0A prefix: Ed25519 indexed signature (index 0)
    - AA prefix: Ed25519 non-indexed signature

    Format: <2-char code><86-char base64url signature> = 88 chars total
    The 86 chars encode 64 bytes (512 bits) of Ed25519 signature.

    Args:
        cesr_sig: CESR-encoded signature string (88 characters).

    Returns:
        Raw 64-byte Ed25519 signature.

    Raises:
        ResolutionFailedError: If format is invalid (maps to PASSPORT_PARSE_FAILED).
    """
    if not cesr_sig:
        raise ResolutionFailedError("Empty CESR signature")

    # Valid CESR Ed25519 signature is exactly 88 characters
    if len(cesr_sig) != 88:
        raise ResolutionFailedError(
            f"Invalid CESR signature length: {len(cesr_sig)}, expected 88"
        )

    # Extract derivation code (first 2 characters)
    code = cesr_sig[:2]

    # Validate derivation code
    valid_codes = ("0A", "0B", "0C", "0D", "AA")
    if code not in valid_codes:
        raise ResolutionFailedError(
            f"Invalid CESR signature derivation code: {code}, "
            f"expected one of {valid_codes}"
        )

    # Extract base64url-encoded signature (remaining 86 characters)
    sig_b64 = cesr_sig[2:]

    # CESR uses URL-safe base64 without padding
    # Add padding for standard base64 decode
    padded = sig_b64 + "=" * (-len(sig_b64) % 4)

    try:
        sig_bytes = base64.urlsafe_b64decode(padded)
    except Exception as e:
        raise ResolutionFailedError(f"Invalid CESR signature encoding: {e}")

    # Ed25519 signature is exactly 64 bytes
    if len(sig_bytes) != 64:
        raise ResolutionFailedError(
            f"Invalid signature length after decode: {len(sig_bytes)}, expected 64"
        )

    return sig_bytes
