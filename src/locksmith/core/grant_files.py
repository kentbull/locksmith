"""Exact held-view Grant files and independent issuer consent, without delivery."""
from contextlib import contextmanager
from types import SimpleNamespace

from keri import kering
from keri.acdc import chaining, ipexing as native
from keri.app.habbing import GroupHab
from keri.core import Parser, Prefixer, SealEvent, messagize
from keri.help import helping
from keri.peer import exchanging

from locksmith.core import credentialing, disclosing, ipexing


def inspect(raw):
    """Extract one finite unanchored native Grant, without authentication or intake."""
    if not raw or len(raw) > 1048576:
        raise ValueError('Select one signed Grant file (at most 1 MiB)')
    stream = bytearray(raw)
    item = Parser(version=kering.Vrsn_2_0).parseOneBare(ims=stream, framed=True, processive=False)
    if (stream or item.serder.pvrsn != kering.Vrsn_2_0 or item.serder.ilk != 'xip'
            or item.serder.route != '/ipex/grant' or item.serder.sad['a'].get('ax', [False])[0]
            or any(value for key, value in vars(item).items()
                if key not in ('serder', 'tsgs', 'cigars', 'ssts', 'nests', 'local'))):
        raise ValueError('Expected one unanchored opening Grant with exact nested evidence')
    return item


def nodes(item):
    return [exchanging.serializeParsedSubstream(node) for node in item.nests]


def wire(item):
    return bytes(messagize(item.serder, tsgs=item.tsgs or None, cigars=item.cigars or None,
        bonds=[SealEvent(*seal) for seal in item.ssts] or None,
        nests=nodes(item) or None, gvrsn=kering.Vrsn_2_0))


def _hab(vault, aid):
    ipexing._require_vault(vault)
    hab = vault.hby.habByPre(aid)
    if hab is None or isinstance(hab, GroupHab):
        raise ValueError('Select an individual identifier in this open vault')
    return hab


def _protected(vault, raw):
    # Local authoring/authentication additions borrow the real native owners, without KRAM registration.
    Parser(version=kering.Vrsn_2_0, kvy=vault.hby.kvy, exc=vault.exc,
           rvy=vault.rvy, rgy=vault.rgy, local=True).parse(ims=bytearray(raw), local=True)


def retained(vault, said):
    ipexing._require_vault(vault)
    message = vault.hby.db.exns.get((said,)) or vault.hby.db.epse.get((said,))
    deadline = vault.hby.db.epsd.get((said,))
    if (message is None or deadline is None or vault.hby.db.erpy.get((said,)) is not None
            or helping.nowUTC() >= deadline.datetime):
        raise ValueError('Prepared Grant is unavailable, terminated or past its original native deadline')
    tsgs, cigars = exchanging.verify(vault.hby, message)
    seals = [(Prefixer(qb64=keys[1]), number, diger)
             for keys, (number, diger) in vault.hby.db.ests.getTopItemIter(keys=(said, ''))]
    return SimpleNamespace(serder=message, tsgs=tsgs, cigars=cigars, ssts=seals,
        nests=exchanging.loadParsedNestedSubstreams(vault.hby, said)), deadline.dts


def _context(vault, item):
    message = item.serder
    result = vault.exc.presentationContext(message.said, xid=message.said,
        sender=message.pre, recipient=message.sad['ri'])
    expected = {}
    for node in item.nests:
        if node.serder.regid:
            expected.setdefault(node.serder.regid, set()).add(node.serder.said)
    if (not expected or result is None or set(result[2]) != set(expected)
            or any(set(result[2][key]) != value for key, value in expected.items())):
        raise ValueError('Exact Grant lacks complete native issuer endorsement and presentation scope')
    return result


def _factors(item):
    return ({('tsg', pre.qb64, number.sn, diger.qb64, sig.qb64)
             for pre, number, diger, signatures in item.tsgs for sig in signatures}
            | {('cigar', cigar.verfer.qb64, cigar.qb64) for cigar in item.cigars}
            | {('seal', pre.qb64, number.sn, diger.qb64) for pre, number, diger in item.ssts})


def _selection(vault, aid, said, source, paths):
    hab = _hab(vault, aid)
    record = credentialing.admission(vault, said, source)
    original = vault.hby.db.exns.get((source,))
    admit = vault.hby.db.exns.get((record.admit,))
    xid = lambda message: message.said if message.ilk == 'xip' else message.sad['x']
    if (original.pvrsn != kering.Vrsn_2_0 or admit.pvrsn != kering.Vrsn_2_0
            or original.sad['ri'] != hab.pre or xid(admit) != xid(original)
            or original.sad['a'].get('ax', [False])[0]
            or (terminal := vault.hby.db.erpy.get((source,))) is None
            or terminal.qb64 != admit.said):
        raise ValueError('Select this local recipient\'s exact native Grant and accepted Admit')
    selected = exchanging.loadParsedNestedSubstreams(vault.hby, source)
    if selected[0].serder.said != said:
        raise ValueError('Selected admission has a different origin')
    if paths:
        selected[0].serder = disclosing.select(selected[0].serder, paths)
    plan = ipexing._disclosure_plan(said, {node.serder.said: node.serder.sad for node in selected})
    if paths:
        plan[0][0][2] = list(paths)
    return hab, original, selected, plan


def capture(vault, grant, *, aid, said, source, recipient, message='', paths=()):
    """Recompute only the exact selected held view; never recreate missing preparation."""
    _, _, selected, plan = _selection(vault, aid, said, source, paths)
    item, deadline = retained(vault, grant)
    body = item.serder
    if (body.pvrsn != kering.Vrsn_2_0 or body.ilk != 'xip' or body.route != '/ipex/grant'
            or body.pre != aid or body.sad['ri'] != recipient or body.sad.get('p')
            or body.sad['q'] != dict(dp=plan) or body.sad['a'] != dict(m=message, o=[said])
            or nodes(item) != [exchanging.serializeParsedSubstream(node) for node in selected]):
        raise ValueError('Prepared Grant differs from the selected admission, disclosure or parties')
    return item, deadline


def prepare(vault, *, aid, said, source, recipient, message='', paths=()):
    hab, original, selected, plan = _selection(vault, aid, said, source, paths)
    if recipient not in vault.hby.kevers:
        raise ValueError('Introduce the selected verifier before preparing a Grant')
    _, _, verdict, records = vault.exc.reverifyGrant(original.said)
    if (not (verdict.verdict == chaining.Verdicts.valid
             or verdict.verdict == chaining.Verdicts.unknown and verdict.retryable)
            or any(record.state != 'issued' for record in records.values())):
        raise ValueError('Preparation requires issued state or retryable unknown current evidence')
    streams = [exchanging.serializeParsedSubstream(node) for node in selected]
    grant, atc = native.grant(hab, recipient, message, origin=streams[0],
        artifacts=streams[1:] or None, modifiers=dict(dp=plan), kind=kering.Kinds.json,
        gvrsn=kering.Vrsn_2_0)
    raw = bytes(grant.raw + atc)
    _protected(vault, raw)
    _, deadline = capture(vault, grant.said, aid=aid, said=said, source=source,
                         recipient=recipient, message=message, paths=paths)
    return grant.said, raw, deadline


@contextmanager
def _endorsing(vault, hab, item):
    """Temporarily admit only this exact selected issuer-owned third-party body to native verification."""
    selected = [node for node in item.nests if node.serder.regid]
    if not selected or any(node.serder.israid != hab.pre
            or (rip := vault.rgy.store.seqEvent(node.serder.regid, 0)) is None
            or rip.israid != hab.pre for node in selected):
        raise ValueError('Every selected registry-backed node must belong to this local issuer')
    handler = vault.exc.routes['/ipex/grant']
    previous = handler.endorsement
    handler.endorsement = (item.serder.raw, tuple(nodes(item)))
    try:
        yield
    finally:
        handler.endorsement = previous


def endorse(vault, raw, *, issuer, grant, sender, recipient):
    """Explicit issuer consent signs the same body and preserves all selected proofs."""
    hab, item = _hab(vault, issuer), inspect(raw)
    body = item.serder
    if body.said != grant or body.pre != sender or body.sad['ri'] != recipient:
        raise ValueError('Select the exact inspected Grant, discloser and verifier')
    with _endorsing(vault, hab, item):
        _protected(vault, wire(item))
        saved, _ = retained(vault, grant)
        if saved.serder.raw != body.raw or nodes(saved) != nodes(item):
            raise ValueError('Native retention differs from the selected Grant')
        addition = inspect(hab.endorse(body, framed=False, gvrsn=kering.Vrsn_2_0))
        item.tsgs.extend(addition.tsgs)
        item.cigars.extend(addition.cigars)
        final = wire(item)
        _protected(vault, final)
        saved, _ = retained(vault, grant)
        _context(vault, saved)
    return final


def resume(vault, raw, *, grant, aid, said, source, recipient, message='', paths=()):
    """Register final authentication only; no delivery, root use, Unblind approval or Admit."""
    options = dict(aid=aid, said=said, source=source, recipient=recipient, message=message, paths=paths)
    original, deadline = capture(vault, grant, **options)  # Before any input import.
    candidate = inspect(raw)
    if (candidate.serder.raw != original.serder.raw or nodes(candidate) != nodes(original)
            or not _factors(original).issubset(_factors(candidate))):
        raise ValueError('Resume permits authentication additions to the exact prepared Grant only')
    kramer = vault.kvy.kramer
    if (kramer is None or not kramer.enabled
            or any(kramer.denial(original.serder).startswith(value) for value in kramer.denials)):
        raise ValueError('Signed-file resume requires ordinary nonexempt KRAM conversation registration')
    key = (aid, grant, grant)
    prior = vault.hby.db.kramTMSC.get(key)
    if prior is not None and prior.rdt:
        raise ValueError('This preparation is already registered; sending is a separate action')
    _protected(vault, raw)
    checked, current = capture(vault, grant, **options)
    if current != deadline:
        raise ValueError('Resume changed the original native deadline')
    _context(vault, checked)
    final = wire(checked)
    # Final bytes enter the ordinary conversation owner once, without delivery consent.
    vault.mbx.parser.parse(ims=bytearray(final), local=True, version=kering.Vrsn_2_0)
    cache = vault.hby.db.kramTMSC.get(key)
    if (cache is None or not cache.rdt or cache.mdt != original.serder.stamp
            or cache.xdt != original.serder.stamp):
        raise ValueError('Ordinary KRAM registration was not accepted; the original timestamp and deadline are unchanged')
    checked, current = capture(vault, grant, **options)
    if current != deadline:
        raise ValueError('Registration changed the original native deadline')
    _context(vault, checked)
    return final, deadline
