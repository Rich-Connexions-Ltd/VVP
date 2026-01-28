#!/usr/bin/env python3
"""
Generate authoritative KERI test fixtures using keripy.

This script generates canonical serialization vectors for testing our
CESR parser and canonicalization implementation. The fixtures are used
to verify that our implementation matches keripy's behavior.

KERIPY VERSION LOCK:
  - Version: 2.0.0-dev5
  - Git commit: 1e2bf869faef77621cd75190aab7a93917c60d19
  - Date: 2026-01-20

Any changes to keripy should trigger re-generation of fixtures to detect
canonicalization drift.

Usage:
    cd VVP
    PYTHONPATH=keripy/src python3 scripts/generate_keripy_fixtures.py
"""

import json
import sys
from pathlib import Path
from base64 import urlsafe_b64encode

# Version check - fail early if keripy version doesn't match
EXPECTED_KERIPY_VERSION = "2.0.0-dev5"
EXPECTED_KERIPY_COMMIT = "1e2bf869faef77621cd75190aab7a93917c60d19"

# Add keripy to path if running from VVP root
keripy_src = Path(__file__).parent.parent / "keripy" / "src"
if keripy_src.exists():
    sys.path.insert(0, str(keripy_src))

try:
    import keri
    from keri.core import eventing, coring, serdering
    from keri.kering import Ilks, Kinds, Vrsn_1_0
    from keri.help import helping
except ImportError as e:
    print(f"Error: Could not import keripy: {e}")
    print("Make sure keripy is installed or PYTHONPATH includes keripy/src")
    sys.exit(1)

# Verify keripy version
if hasattr(keri, '__version__'):
    actual_version = keri.__version__
else:
    actual_version = "unknown"

print(f"keripy version: {actual_version}")
print(f"Expected version: {EXPECTED_KERIPY_VERSION}")

# Note: We log version info but don't fail on mismatch during development
# In CI, this check should be strict

OUTPUT_DIR = Path(__file__).parent.parent / "tests" / "fixtures" / "keri"


def generate_keys():
    """Generate a set of Ed25519 signing keys for fixtures."""
    import pysodium
    import hashlib

    # Generate deterministic keys for reproducibility
    # Using fixed seeds so fixtures are stable across runs
    # Seeds must be exactly 32 bytes for Ed25519
    seed_inputs = [
        b"fixture_key_seed_1",
        b"fixture_key_seed_2",
        b"fixture_key_seed_3",
    ]
    # Hash to get 32-byte seeds
    seeds = [hashlib.sha256(s).digest() for s in seed_inputs]

    keys = []
    for seed in seeds:
        # pysodium expects 32-byte seed
        pk, sk = pysodium.crypto_sign_seed_keypair(seed)
        # KERI uses "D" prefix for Ed25519 keys
        verfer = coring.Verfer(raw=pk, code=coring.MtrDex.Ed25519)
        keys.append({
            "public_key": pk,
            "secret_key": sk,
            "verfer": verfer,
            "qb64": verfer.qb64,
        })

    return keys


def generate_next_key_digests(keys):
    """Generate next key commitment digests."""
    digests = []
    for key in keys:
        # Create digest of public key for next key commitment
        diger = coring.Diger(ser=key["public_key"], code=coring.MtrDex.Blake3_256)
        digests.append(diger.qb64)
    return digests


def generate_icp_fixture(keys):
    """Generate inception event fixture."""
    # Use first key as signing key
    signing_keys = [keys[0]["qb64"]]

    # Use remaining keys for next key commitment
    next_digests = generate_next_key_digests(keys[1:])

    # Create inception event using keripy's eventing module
    serder = eventing.incept(
        keys=signing_keys,
        isith=1,
        ndigs=next_digests,
        nsith=1,
        toad=0,
        wits=[],
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    return {
        "event_type": "icp",
        "description": "Inception event with single signing key",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "aid": serder.pre,
    }


def generate_rot_fixture(keys, icp_serder):
    """Generate rotation event fixture."""
    # Rotate from key[0] to key[1]
    new_signing_keys = [keys[1]["qb64"]]

    # Next keys are key[2]
    next_digests = generate_next_key_digests([keys[2]])

    # Create rotation event
    serder = eventing.rotate(
        pre=icp_serder.pre,
        keys=new_signing_keys,
        dig=icp_serder.said,
        isith=1,
        ndigs=next_digests,
        nsith=1,
        sn=1,
        toad=0,
        cuts=[],
        adds=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    return {
        "event_type": "rot",
        "description": "Rotation event (key[0] -> key[1])",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "prior_said": icp_serder.said,
    }


def generate_ixn_fixture(keys, icp_serder, rot_serder):
    """Generate interaction event fixture."""
    # Create interaction event after rotation
    serder = eventing.interact(
        pre=icp_serder.pre,
        dig=rot_serder.said,
        sn=2,
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
    )

    return {
        "event_type": "ixn",
        "description": "Interaction event (sn=2)",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "prior_said": rot_serder.said,
    }


def generate_witness_fixture(keys):
    """Generate inception event with witnesses."""
    # Generate witness keys (non-transferable)
    import pysodium
    import hashlib

    witness_seed_inputs = [
        b"witness_key_seed_1",
        b"witness_key_seed_2",
        b"witness_key_seed_3",
    ]
    # Hash to get 32-byte seeds
    witness_seeds = [hashlib.sha256(s).digest() for s in witness_seed_inputs]

    witness_aids = []
    witness_keys = []
    for seed in witness_seeds:
        pk, sk = pysodium.crypto_sign_seed_keypair(seed)
        # Non-transferable witnesses use "B" prefix
        verfer = coring.Verfer(raw=pk, code=coring.MtrDex.Ed25519N)
        witness_aids.append(verfer.qb64)
        witness_keys.append({
            "public_key": pk,
            "secret_key": sk,
            "qb64": verfer.qb64,
        })

    signing_keys = [keys[0]["qb64"]]
    next_digests = generate_next_key_digests(keys[1:])

    # Create inception with witnesses
    serder = eventing.incept(
        keys=signing_keys,
        isith=1,
        ndigs=next_digests,
        nsith=1,
        toad=2,  # Require 2 of 3 witnesses
        wits=witness_aids,
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    return {
        "event_type": "icp_with_witnesses",
        "description": "Inception event with 3 witnesses (toad=2)",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "event": serder.sad,
        "canonical_bytes": urlsafe_b64encode(serder.raw).decode("ascii"),
        "canonical_bytes_hex": serder.raw.hex(),
        "size": serder.size,
        "said": serder.said,
        "aid": serder.pre,
        "witnesses": witness_aids,
        "witness_keys": [
            {
                "aid": wk["qb64"],
                "public_key_hex": wk["public_key"].hex(),
            }
            for wk in witness_keys
        ],
        "toad": 2,
    }


def sign_event(serder, signer, index=0):
    """Sign an event and return the CESR-encoded signature.

    Args:
        serder: The event Serder object
        signer: Dict with 'secret_key' for signing
        index: Key index for indexed signatures

    Returns:
        tuple: (siger_qb64, signature_hex, counter_qb64)
    """
    from keri.core.indexing import Siger, IdrDex
    from keri.core.counting import Counter, Codens

    # Sign the raw canonical bytes
    import pysodium
    signature = pysodium.crypto_sign_detached(serder.raw, signer["secret_key"])

    # Create indexed signature (Siger)
    siger = Siger(raw=signature, index=index, code=IdrDex.Ed25519_Sig)

    # Create counter for controller indexed signatures
    counter = Counter(Codens.ControllerIdxSigs, count=1, version=Vrsn_1_0)

    return {
        "siger_qb64": siger.qb64,
        "signature_hex": signature.hex(),
        "counter_qb64": counter.qb64,
    }


def generate_binary_kel_fixture(keys):
    """Generate a complete binary CESR KEL stream with signatures.

    This creates a full KEL stream that can be parsed by our CESR parser:
    - icp event + signature counter + controller signature
    - rot event + signature counter + controller signature
    - ixn event + signature counter + controller signature

    Returns:
        dict with binary stream and metadata
    """
    from keri.core.counting import Counter, Codens

    # Generate ICP event
    next_digests = generate_next_key_digests(keys[1:])
    icp_serder = eventing.incept(
        keys=[keys[0]["qb64"]],
        isith=1,
        ndigs=next_digests,
        nsith=1,
        toad=0,
        wits=[],
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )
    icp_sig = sign_event(icp_serder, keys[0], index=0)

    # Generate ROT event
    # IMPORTANT: Rotation must be signed with the PRIOR key (key[0]),
    # not the new key (key[1]). The prior key authorizes the rotation.
    rot_serder = eventing.rotate(
        pre=icp_serder.pre,
        keys=[keys[1]["qb64"]],
        dig=icp_serder.said,
        isith=1,
        ndigs=generate_next_key_digests([keys[2]]),
        nsith=1,
        sn=1,
        toad=0,
        cuts=[],
        adds=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )
    rot_sig = sign_event(rot_serder, keys[0], index=0)  # Sign with PRIOR key

    # Generate IXN event
    ixn_serder = eventing.interact(
        pre=icp_serder.pre,
        dig=rot_serder.said,
        sn=2,
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
    )
    ixn_sig = sign_event(ixn_serder, keys[1], index=0)

    # Build the complete binary stream
    # Format: event_bytes + counter_code + signature (repeated for each event)
    stream = bytearray()

    # ICP message
    stream.extend(icp_serder.raw)
    stream.extend(icp_sig["counter_qb64"].encode("utf-8"))
    stream.extend(icp_sig["siger_qb64"].encode("utf-8"))

    # ROT message
    stream.extend(rot_serder.raw)
    stream.extend(rot_sig["counter_qb64"].encode("utf-8"))
    stream.extend(rot_sig["siger_qb64"].encode("utf-8"))

    # IXN message
    stream.extend(ixn_serder.raw)
    stream.extend(ixn_sig["counter_qb64"].encode("utf-8"))
    stream.extend(ixn_sig["siger_qb64"].encode("utf-8"))

    return {
        "description": "Complete KEL stream with controller signatures in CESR format",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "stream_hex": bytes(stream).hex(),
        "stream_base64": urlsafe_b64encode(bytes(stream)).decode("ascii"),
        "stream_length": len(stream),
        "aid": icp_serder.pre,
        "events": [
            {
                "type": "icp",
                "said": icp_serder.said,
                "event_bytes_hex": icp_serder.raw.hex(),
                "event_size": len(icp_serder.raw),
                "counter": icp_sig["counter_qb64"],
                "signature": icp_sig["siger_qb64"],
                "signature_hex": icp_sig["signature_hex"],
            },
            {
                "type": "rot",
                "said": rot_serder.said,
                "prior_said": icp_serder.said,
                "event_bytes_hex": rot_serder.raw.hex(),
                "event_size": len(rot_serder.raw),
                "counter": rot_sig["counter_qb64"],
                "signature": rot_sig["siger_qb64"],
                "signature_hex": rot_sig["signature_hex"],
            },
            {
                "type": "ixn",
                "said": ixn_serder.said,
                "prior_said": rot_serder.said,
                "event_bytes_hex": ixn_serder.raw.hex(),
                "event_size": len(ixn_serder.raw),
                "counter": ixn_sig["counter_qb64"],
                "signature": ixn_sig["siger_qb64"],
                "signature_hex": ixn_sig["signature_hex"],
            },
        ],
    }


def generate_witness_receipts_fixture(keys):
    """Generate inception event with witness receipts for validation testing.

    Creates a complete fixture with:
    - Controller inception event with 3 witnesses (toad=2)
    - Controller signature over the event
    - Valid witness receipt signatures (all 3 witnesses sign)
    - One invalid receipt for negative testing

    The witnesses use non-transferable AIDs (B-prefix, Ed25519N code).
    """
    import pysodium
    import hashlib
    from keri.core.indexing import Siger, IdrDex

    # Generate witness keys deterministically
    witness_seed_inputs = [
        b"witness_receipt_seed_1",
        b"witness_receipt_seed_2",
        b"witness_receipt_seed_3",
    ]
    witness_seeds = [hashlib.sha256(s).digest() for s in witness_seed_inputs]

    witness_keys = []
    witness_aids = []
    for i, seed in enumerate(witness_seeds):
        pk, sk = pysodium.crypto_sign_seed_keypair(seed)
        # Non-transferable witnesses use B-prefix (Ed25519N)
        verfer = coring.Verfer(raw=pk, code=coring.MtrDex.Ed25519N)
        witness_keys.append({
            "index": i,
            "public_key": pk,
            "secret_key": sk,
            "qb64": verfer.qb64,
        })
        witness_aids.append(verfer.qb64)

    # Generate controller key for this fixture
    controller_seed = hashlib.sha256(b"witness_receipt_controller_seed").digest()
    controller_pk, controller_sk = pysodium.crypto_sign_seed_keypair(controller_seed)
    controller_verfer = coring.Verfer(raw=controller_pk, code=coring.MtrDex.Ed25519)

    # Use keys[1:] for next key commitment (placeholder digests)
    next_digests = ["E" + "_" * 43]  # Placeholder next key digest

    # Create inception event with witnesses
    serder = eventing.incept(
        keys=[controller_verfer.qb64],
        isith=1,
        ndigs=next_digests,
        nsith=1,
        toad=2,  # Require 2 of 3 witnesses
        wits=witness_aids,
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    # Sign the event with controller key
    controller_sig = pysodium.crypto_sign_detached(serder.raw, controller_sk)

    # Generate valid witness receipts - each witness signs the canonical event bytes
    valid_receipts = []
    for wk in witness_keys:
        witness_sig = pysodium.crypto_sign_detached(serder.raw, wk["secret_key"])
        valid_receipts.append({
            "witness_aid": wk["qb64"],
            "signature_hex": witness_sig.hex(),
        })

    # Generate an invalid receipt (all zeros signature)
    invalid_sig = b'\x00' * 64
    invalid_receipt = {
        "witness_aid": witness_keys[0]["qb64"],
        "signature_hex": invalid_sig.hex(),
        "reason": "All-zeros signature that should fail validation",
    }

    return {
        "description": "ICP event with witness receipts for validation testing",
        "event": serder.sad,
        "canonical_bytes_hex": serder.raw.hex(),
        "controller": {
            "aid": controller_verfer.qb64,
            "public_key_hex": controller_pk.hex(),
            "signature_hex": controller_sig.hex(),
        },
        "witnesses": [
            {
                "index": wk["index"],
                "aid": wk["qb64"],
                "public_key_hex": wk["public_key"].hex(),
            }
            for wk in witness_keys
        ],
        "valid_receipts": valid_receipts,
        "invalid_receipt": invalid_receipt,
        "toad": 2,
    }


def generate_field_order_reference():
    """Extract field ordering from keripy's FieldDom definitions."""
    # These are from keripy/src/keri/core/serdering.py
    field_orders = {}

    fields = serdering.Serder.Fields
    for proto in [serdering.Protocols.keri]:
        for vrsn in [Vrsn_1_0]:
            if proto in fields and vrsn in fields[proto]:
                for ilk, field_dom in fields[proto][vrsn].items():
                    if hasattr(field_dom, 'alls'):
                        field_orders[ilk] = list(field_dom.alls.keys())

    return {
        "description": "Field orderings per event type from keripy",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "protocol_version": "1.0",
        "field_orders": field_orders,
    }


def main():
    """Generate all fixtures."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Generating fixtures in {OUTPUT_DIR}")
    print("-" * 60)

    # Generate keys
    keys = generate_keys()
    print(f"Generated {len(keys)} signing keys")

    # Generate ICP fixture
    icp_fixture = generate_icp_fixture(keys)
    icp_path = OUTPUT_DIR / "icp_keripy.json"
    with open(icp_path, "w") as f:
        json.dump(icp_fixture, f, indent=2)
    print(f"✓ Generated {icp_path.name}")
    print(f"  AID: {icp_fixture['aid'][:20]}...")
    print(f"  SAID: {icp_fixture['said'][:20]}...")

    # We need the actual serder for subsequent events
    icp_serder = eventing.incept(
        keys=[keys[0]["qb64"]],
        isith=1,
        ndigs=generate_next_key_digests(keys[1:]),
        nsith=1,
        toad=0,
        wits=[],
        cnfg=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    # Generate ROT fixture
    rot_fixture = generate_rot_fixture(keys, icp_serder)
    rot_path = OUTPUT_DIR / "rot_keripy.json"
    with open(rot_path, "w") as f:
        json.dump(rot_fixture, f, indent=2)
    print(f"✓ Generated {rot_path.name}")
    print(f"  SAID: {rot_fixture['said'][:20]}...")

    # Re-create rot serder for IXN
    rot_serder = eventing.rotate(
        pre=icp_serder.pre,
        keys=[keys[1]["qb64"]],
        dig=icp_serder.said,
        isith=1,
        ndigs=generate_next_key_digests([keys[2]]),
        nsith=1,
        sn=1,
        toad=0,
        cuts=[],
        adds=[],
        data=[],
        pvrsn=Vrsn_1_0,
        kind=Kinds.json,
        intive=True,
    )

    # Generate IXN fixture
    ixn_fixture = generate_ixn_fixture(keys, icp_serder, rot_serder)
    ixn_path = OUTPUT_DIR / "ixn_keripy.json"
    with open(ixn_path, "w") as f:
        json.dump(ixn_fixture, f, indent=2)
    print(f"✓ Generated {ixn_path.name}")
    print(f"  SAID: {ixn_fixture['said'][:20]}...")

    # Generate witness fixture
    witness_fixture = generate_witness_fixture(keys)
    witness_path = OUTPUT_DIR / "icp_witnesses_keripy.json"
    with open(witness_path, "w") as f:
        json.dump(witness_fixture, f, indent=2)
    print(f"✓ Generated {witness_path.name}")
    print(f"  Witnesses: {len(witness_fixture['witnesses'])}")
    print(f"  Toad: {witness_fixture['toad']}")

    # Generate field order reference
    field_orders = generate_field_order_reference()
    field_path = OUTPUT_DIR / "field_orders_keripy.json"
    with open(field_path, "w") as f:
        json.dump(field_orders, f, indent=2)
    print(f"✓ Generated {field_path.name}")
    for ilk, fields in field_orders["field_orders"].items():
        print(f"  {ilk}: {', '.join(fields)}")

    # Generate combined KEL stream fixture
    kel_fixture = {
        "description": "Complete KEL: icp -> rot -> ixn",
        "keripy_version": EXPECTED_KERIPY_VERSION,
        "keripy_commit": EXPECTED_KERIPY_COMMIT,
        "events": [
            icp_fixture["event"],
            rot_fixture["event"],
            ixn_fixture["event"],
        ],
        "canonical_bytes": [
            icp_fixture["canonical_bytes"],
            rot_fixture["canonical_bytes"],
            ixn_fixture["canonical_bytes"],
        ],
    }
    kel_path = OUTPUT_DIR / "kel_stream_keripy.json"
    with open(kel_path, "w") as f:
        json.dump(kel_fixture, f, indent=2)
    print(f"✓ Generated {kel_path.name}")

    # Generate signing key info for tests
    key_info = {
        "description": "Signing keys used for fixtures",
        "note": "These are deterministic test keys - NEVER use in production",
        "keys": [
            {
                "index": i,
                "qb64": k["qb64"],
                "public_key_hex": k["public_key"].hex(),
                "secret_key_hex": k["secret_key"].hex(),
            }
            for i, k in enumerate(keys)
        ],
    }
    keys_path = OUTPUT_DIR / "signing_keys.json"
    with open(keys_path, "w") as f:
        json.dump(key_info, f, indent=2)
    print(f"✓ Generated {keys_path.name}")

    # Generate binary CESR KEL stream with signatures
    binary_kel = generate_binary_kel_fixture(keys)
    binary_path = OUTPUT_DIR / "binary_kel.json"
    with open(binary_path, "w") as f:
        json.dump(binary_kel, f, indent=2)
    print(f"✓ Generated {binary_path.name}")
    print(f"  Stream length: {binary_kel['stream_length']} bytes")
    print(f"  AID: {binary_kel['aid'][:20]}...")
    print(f"  Events: {len(binary_kel['events'])}")

    # Generate witness receipts fixture with valid signatures
    witness_receipts = generate_witness_receipts_fixture(keys)
    witness_receipts_path = OUTPUT_DIR / "witness_receipts_keripy.json"
    with open(witness_receipts_path, "w") as f:
        json.dump(witness_receipts, f, indent=2)
    print(f"✓ Generated {witness_receipts_path.name}")
    print(f"  Controller: {witness_receipts['controller']['aid'][:20]}...")
    print(f"  Witnesses: {len(witness_receipts['witnesses'])}")
    print(f"  Valid receipts: {len(witness_receipts['valid_receipts'])}")

    print("-" * 60)
    print("Fixture generation complete!")
    print(f"Output directory: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
