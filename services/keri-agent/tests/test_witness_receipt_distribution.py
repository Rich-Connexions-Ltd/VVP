"""Integration test: witness receipt distribution and fullyWitnessed.

Tests Phase 2 of witness publishing — distributing all witness indexed
signatures to every witness so that each witness passes fullyWitnessed().

Uses the keripy-proven receipt (rct) event approach with -B WitnessIdxSigs
attachment, matching the pattern from keripy's test_witness.py.

Sprint 70: Automatic Witness Re-Publishing on Startup.
"""
from keri import core
from keri.app import habbing
from keri.core import eventing, parsing, serdering
from keri.core.indexing import Siger
from keri.db import dbing


def test_receipt_distribution_via_receipt_event():
    """Phase 2 approach A: Send rct event with witness indexed sigs.

    This is the keripy-proven approach from test_witness.py.
    Each witness receives an rct event containing all witness indexed
    signatures. The Parser dispatches to processReceiptWitness which
    verifies and stores them in db.wigs via addWig.
    """
    salt = core.Salter(raw=b'abcdef0123456789').qb64

    with habbing.openHby(name="ctrl", base="test", salt=salt) as ctrlHby, \
         habbing.openHby(name="w0", base="test", salt=salt) as w0Hby, \
         habbing.openHby(name="w1", base="test", salt=salt) as w1Hby, \
         habbing.openHby(name="w2", base="test", salt=salt) as w2Hby:

        # Create non-transferable witness habs
        w0Hab = w0Hby.makeHab(name='w0', isith='1', icount=1, transferable=False)
        w1Hab = w1Hby.makeHab(name='w1', isith='1', icount=1, transferable=False)
        w2Hab = w2Hby.makeHab(name='w2', isith='1', icount=1, transferable=False)

        wits = [w0Hab.pre, w1Hab.pre, w2Hab.pre]

        # Create non-local Keverys for witnesses (to process controller events)
        w0Kvy = eventing.Kevery(db=w0Hab.db, lax=False, local=False)
        w1Kvy = eventing.Kevery(db=w1Hab.db, lax=False, local=False)
        w2Kvy = eventing.Kevery(db=w2Hab.db, lax=False, local=False)

        witKvys = [w0Kvy, w1Kvy, w2Kvy]
        witHabs = [w0Hab, w1Hab, w2Hab]

        # Create controller hab with 3 witnesses, toad=3
        ctrlHab = ctrlHby.makeHab(
            name='ctrl', isith='1', icount=1,
            toad=3, wits=wits,
        )
        assert ctrlHab.kever.wits == wits
        assert ctrlHab.kever.toader.num == 3
        ctrlKvy = eventing.Kevery(db=ctrlHab.db, lax=False, local=False)

        # --- Phase 1: Send inception to witnesses, collect receipts ---
        icpMsg = ctrlHab.makeOwnInception()
        rctMsgs = []
        for i, kvy in enumerate(witKvys):
            parsing.Parser().parse(ims=bytearray(icpMsg), kvy=kvy, local=True)
            assert kvy.kevers[ctrlHab.pre].sn == 0
            rctMsg = witHabs[i].processCues(kvy.cues)
            rctMsgs.append(rctMsg)

        # Process receipts on controller so controller's db has all wigers
        for msg in rctMsgs:
            parsing.Parser().parse(ims=bytearray(msg), kvy=ctrlKvy, local=True)

        # Controller should have 3 wigers
        dgkey = dbing.dgKey(pre=ctrlHab.pre, dig=ctrlHab.kever.serder.said)
        wigs = ctrlHab.db.getWigs(dgkey)
        assert len(wigs) == 3, f"Controller should have 3 wigers, got {len(wigs)}"

        # Each witness currently has only 1 wiger (its own)
        for i, kvy in enumerate(witKvys):
            w_wigs = kvy.db.getWigs(dgkey)
            assert len(w_wigs) == 1, (
                f"Witness {i} should have 1 wiger before Phase 2, got {len(w_wigs)}"
            )

        # --- Phase 2: Distribute all wigers via receipt event ---
        wigers = [Siger(qb64b=bytes(wig)) for wig in wigs]
        rserder = eventing.receipt(
            pre=ctrlHab.pre,
            sn=ctrlHab.kever.sn,
            said=ctrlHab.kever.serder.said,
        )
        rctWitMsg = eventing.messagize(serder=rserder, wigers=wigers)

        for i, kvy in enumerate(witKvys):
            parsing.Parser().parse(
                ims=bytearray(rctWitMsg), kvy=kvy, local=True,
            )
            w_wigs = kvy.db.getWigs(dgkey)
            assert len(w_wigs) == 3, (
                f"Witness {i} should have 3 wigers after receipt distribution, "
                f"got {len(w_wigs)}"
            )

        # Verify fullyWitnessed
        for i, kvy in enumerate(witKvys):
            assert kvy.db.fullyWitnessed(ctrlHab.kever.serder), (
                f"Witness {i} should be fullyWitnessed"
            )



def test_receipt_distribution_via_http_simulation():
    """Simulate the full HTTP flow for Phase 2 receipt distribution.

    This test simulates what ReceiptEnd.on_post does: it deserializes
    the JSON body, re-serializes it, combines with CESR attachment,
    and processes through parseOne. This catches serialization issues
    that wouldn't appear in direct-parsing tests.
    """
    salt = core.Salter(raw=b'abcdef0123456789').qb64

    with habbing.openHby(name="ctrl3", base="test", salt=salt) as ctrlHby, \
         habbing.openHby(name="w0c", base="test", salt=salt) as w0Hby, \
         habbing.openHby(name="w1c", base="test", salt=salt) as w1Hby, \
         habbing.openHby(name="w2c", base="test", salt=salt) as w2Hby:

        w0Hab = w0Hby.makeHab(name='w0c', isith='1', icount=1, transferable=False)
        w1Hab = w1Hby.makeHab(name='w1c', isith='1', icount=1, transferable=False)
        w2Hab = w2Hby.makeHab(name='w2c', isith='1', icount=1, transferable=False)

        wits = [w0Hab.pre, w1Hab.pre, w2Hab.pre]

        w0Kvy = eventing.Kevery(db=w0Hab.db, lax=False, local=False)
        w1Kvy = eventing.Kevery(db=w1Hab.db, lax=False, local=False)
        w2Kvy = eventing.Kevery(db=w2Hab.db, lax=False, local=False)

        witKvys = [w0Kvy, w1Kvy, w2Kvy]
        witHabs = [w0Hab, w1Hab, w2Hab]

        ctrlHab = ctrlHby.makeHab(
            name='ctrl3', isith='1', icount=1,
            toad=3, wits=wits,
        )
        ctrlKvy = eventing.Kevery(db=ctrlHab.db, lax=False, local=False)

        # Phase 1
        icpMsg = ctrlHab.makeOwnInception()
        rctMsgs = []
        for i, kvy in enumerate(witKvys):
            parsing.Parser().parse(ims=bytearray(icpMsg), kvy=kvy, local=True)
            rctMsg = witHabs[i].processCues(kvy.cues)
            rctMsgs.append(rctMsg)

        for msg in rctMsgs:
            parsing.Parser().parse(ims=bytearray(msg), kvy=ctrlKvy, local=True)

        # Get wigers from controller's db
        dgkey = dbing.dgKey(pre=ctrlHab.pre, dig=ctrlHab.kever.serder.said)
        wigs = ctrlHab.db.getWigs(dgkey)
        assert len(wigs) == 3

        # Build receipt message (proven approach)
        wigers = [Siger(qb64b=bytes(wig)) for wig in wigs]
        rserder = eventing.receipt(
            pre=ctrlHab.pre,
            sn=ctrlHab.kever.sn,
            said=ctrlHab.kever.serder.said,
        )
        rctWitMsg = eventing.messagize(serder=rserder, wigers=wigers)

        # Simulate HTTP: split into JSON body + CESR attachment
        rct_parsed = bytearray(rctWitMsg)
        rct_serder = serdering.SerderKERI(raw=rct_parsed)
        json_body = bytes(rct_serder.raw)
        cesr_attachment = bytes(rct_parsed[rct_serder.size:])

        # Simulate ReceiptEnd-style recombination
        import json as json_mod
        payload = json_mod.loads(json_body)
        re_serder = serdering.SerderKERI(sad=payload, kind=eventing.Kinds.json)
        recombined = bytearray(re_serder.raw)
        recombined.extend(cesr_attachment)

        # Verify re-serialization is byte-identical
        assert bytes(re_serder.raw) == json_body, (
            "Re-serialized JSON should be byte-identical to original"
        )

        # Process on each witness
        for i, kvy in enumerate(witKvys):
            parsing.Parser().parse(
                ims=bytearray(recombined), kvy=kvy, local=True,
            )
            w_wigs = kvy.db.getWigs(dgkey)
            assert len(w_wigs) == 3, (
                f"Witness {i}: expected 3 wigers after HTTP-simulated receipt, "
                f"got {len(w_wigs)}"
            )
            assert kvy.db.fullyWitnessed(ctrlHab.kever.serder), (
                f"Witness {i} should be fullyWitnessed"
            )
