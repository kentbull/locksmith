# -*- encoding: utf-8 -*-
"""
locksmith.core.grouping module

Doers and helpers for KERI group multisig identifier operations.
"""
from ordered_set import OrderedSet as oset

from hio.base import doing
from keri import help, kering
from keri.app import grouping as keri_grouping
from keri.app import habbing as keri_habbing
from keri.app import organizing
from keri.core import coring, messagize
from keri.core.serdering import SerderKERI
from keri.peer.exchanging import serializeParsedSubstream
from keri.peer import exchanging

from locksmith.db.basing import IdentifierMetaInfo

logger = help.ogler.getLogger(__name__)


def registry_proposal(vault, said):
    """Authenticate an exact core TEL/anchor pair without contributing a signature."""
    wrapper, _ = exchanging.cloneMessage(vault.hby, said)
    if (wrapper is None or wrapper.pvrsn != kering.Vrsn_2_0
            or wrapper.route not in ('/multisig/rip', '/multisig/bup') or not vault.exc.complete(said)):
        raise ValueError('Select an authenticated v2 group registry proposal')
    children = exchanging.loadParsedNestedSubstreams(vault.hby, said)
    vault.mux.validate(wrapper, nests=children)
    tel, anchor = [child.serder for child in children]
    group = vault.hby.habByPre(wrapper.sad['a']['gid'])
    if (not isinstance(group, keri_habbing.GroupHab) or not group.accepted or group.mhab is None
            or group.mhab.pre not in vault.hby.db.signingMembers(pre=group.pre)):
        raise ValueError('Registry approval requires an accepted local group signing member')
    if anchor.sn != group.kever.sn + 1 or anchor.sad['p'] != group.kever.serder.said:
        raise ValueError('Registry anchor does not extend the current group event')
    return wrapper, children, group


def pending_registry_proposals(vault):
    """Select retained remote proposals still awaiting this member's explicit approval."""
    proposals = []
    for _, note in vault.notifier.noter.notes.getTopItemIter():
        if note.attrs.get('r') not in ('/multisig/rip', '/multisig/bup'):
            continue
        try:
            wrapper, children, group = registry_proposal(vault, note.attrs['d'])
            approved = any((retained := vault.hby.db.exns.get((diger.qb64,))) is not None
                           and retained.pre == group.mhab.pre
                           and keri_grouping.sameRegistryProposal(retained, wrapper)
                           for diger in vault.hby.db.meids.get((children[1].serder.said,)))
            if not approved and wrapper.pre != group.mhab.pre:
                proposals.append(wrapper)
        except (ValueError, kering.ValidationError):
            continue
    return proposals


def approve_registry_proposal(vault, said, prior, auths=None):
    """Revalidate the reviewed parent, then sign and queue only the retained anchor."""
    wrapper, children, group = registry_proposal(vault, said)
    if group.kever.serder.said != prior:
        raise ValueError('Group changed while registry approval was pending; review the current proposal again')
    anchor = children[1].serder
    wits = [wit for wit in group.kever.wits if wit not in anchor.sad.get('br', [])]
    wits.extend(anchor.sad.get('ba', []))
    if set(auths or {}) - set(wits):
        raise ValueError('Authorization names a witness outside this anchor witness set')
    if anchor.ilk in ('rot', 'drt'):
        own = group.rotate(serder=anchor, smids=group.smids, rmids=group.rmids,
                           gvrsn=kering.Vrsn_2_0)
    else:
        own = messagize(anchor, sigers=group.sign(anchor.raw), gvrsn=kering.Vrsn_2_0)
        vault.mbx.parser.parse(ims=bytearray(own), local=True)
    build = keri_grouping.multisigRipExn if children[0].serder.ilk == 'rip' else keri_grouping.multisigBupExn
    options = {} if children[0].serder.ilk == 'rip' else dict(rgy=vault.rgy)
    proposal, attachments = build(group, serializeParsedSubstream(children[0]), own,
                                  usage=wrapper.sad['a'].get('usage'), **options)
    vault.mbx.parser.parse(ims=bytearray(proposal.raw + attachments), local=True)
    vault.counselor.start(group, coring.Prefixer(qb64=group.pre), coring.Number(num=anchor.sn),
                          coring.Diger(qb64=anchor.said), auths=auths)
    for member in vault.hby.db.signingMembers(pre=group.pre):
        if member != group.mhab.pre:
            vault.postman.send(src=group.mhab.pre, dest=member, topic='multisig',
                               serder=proposal, attachment=attachments, stream=True)
    vault.signals.emit_doer_event('GroupRegistry', 'contribution_queued', {'said': proposal.said})
    return proposal


def inception_proposal(vault, said):
    """Read one authenticated v2 KERI proposal before showing or approving it."""
    exn, _ = exchanging.cloneMessage(vault.hby, said=said)
    if (exn is None or exn.pvrsn != kering.Vrsn_2_0
            or exn.route != '/multisig/icp' or not vault.exc.complete(said)):
        raise ValueError('Select an authenticated v2 KERI group inception proposal')
    children = exchanging.loadParsedNestedSubstreams(vault.hby, said)
    vault.mux.validate(exn, nests=children)
    child = children[0]['serder'] if isinstance(children[0], dict) else children[0].serder
    payload = exn.sad['a']
    if child.pvrsn != kering.Vrsn_2_0 or child.pre != payload['gid']:
        raise ValueError('Group inception does not match the selected v2 KERI group')
    smids, rmids = payload['smids'], payload.get('rmids', payload['smids'])
    if exn.pre not in smids:
        raise ValueError('Group inception proposer is not a signing member')
    verfers, digers = vault.hby.extractMerfersMigers(smids, rmids)
    if child.keys != [key.qb64 for key in verfers] or child.ndigs != [key.qb64 for key in digers]:
        raise ValueError('Group inception does not match the accepted member key states')
    return exn, child


def get_contacts_for_multisig(app):
    """
    Get contacts eligible for multisig participation.
    Returns list of dicts with id, alias keys.
    Filters to transferable identifiers only.

    Args:
        app: Application instance with vault

    Returns:
        list: List of dicts with 'id', 'alias' keys for eligible contacts
    """
    org = organizing.Organizer(hby=app.vault.hby)
    contacts = org.list()
    kevers = app.vault.hby.kevers

    eligible = []
    for contact in contacts:
        pre = contact['id']
        # Filter out remote multisig identifiers (multiple signing keys)
        if pre in kevers and kevers[pre].transferable and len(kevers[pre].verfers) == 1:
            eligible.append({
                'id': pre,
                'alias': contact.get('alias', '')
            })
    return eligible


def extract_smids_from_selections(app, mhab_alias, selected_contacts):
    """
    Build smids list from local hab and selected contacts.

    Args:
        app: Application instance with vault
        mhab_alias: Alias of the local member hab
        selected_contacts: List of selected contact dicts with 'id' key

    Returns:
        list: List of qb64 AIDs for smids
    """
    mhab = app.vault.hby.habByName(mhab_alias)
    if not mhab:
        raise ValueError(f"Local identifier '{mhab_alias}' not found")

    smids = [mhab.pre]
    for contact in selected_contacts:
        pre = contact.get('id')
        if pre and pre not in smids:
            smids.append(pre)

    return smids


def resolve_member_key_states(hby, smids, rmids):
    """
    Resolve member key states for group rotation.

    Each member contributes verfers[0] (current signing key) and ndigers[0]
    (next rotation key digest) per keripy convention.

    Args:
        hby: Habery instance
        smids: List of signing member AIDs
        rmids: List of rotation member AIDs

    Returns:
        tuple: (merfers, migers) - lists of Verfer and Diger instances
    """
    merfers = []
    for smid in smids:
        if smid not in hby.kevers:
            raise kering.ConfigurationError(f"Unknown signing member {smid}")
        merfers.append(hby.kevers[smid].verfers[0])

    migers = []
    for rmid in rmids:
        if rmid not in hby.kevers:
            raise kering.ConfigurationError(f"Unknown rotation member {rmid}")
        migers.append(hby.kevers[rmid].ndigers[0])

    return merfers, migers


def get_shared_witnesses(ghab):
    """
    Get witnesses shared between the group hab and the local member hab.

    Used to determine which witnesses need post-counselor TOTP authentication.

    Args:
        ghab: GroupHab instance

    Returns:
        list: List of witness AIDs shared between group and local member
    """
    group_wits = set(ghab.kever.wits)
    mhab_wits = set(ghab.mhab.kever.wits)
    return list(group_wits.intersection(mhab_wits))


def rotate_group_identifier(app, ghab, isith=None, nsith=None, toad=None,
                            cuts=None, adds=None, smids=None, rmids=None):
    """
    Initiate a group multisig rotation.

    Creates and launches a GroupMultisigRotateDoer.

    Args:
        app: Application instance with vault
        ghab: GroupHab instance to rotate
        isith: Current signing threshold
        nsith: Next signing threshold
        toad: Witness threshold after rotation
        cuts: List of witness AIDs to remove
        adds: List of witness AIDs to add
        smids: Signing member AIDs (defaults to current)
        rmids: Rotation member AIDs (defaults to smids)
    """
    doer = GroupMultisigRotateDoer(
        app=app, ghab=ghab, smids=smids, rmids=rmids,
        isith=isith, nsith=nsith, toad=toad, cuts=cuts, adds=adds,
        signal_bridge=app.vault.signals
    )
    app.vault.extend([doer])


def get_pending_multisig_rotation_proposals(app):
    """
    Get all pending multisig rotation proposals from notifier.

    Args:
        app: Application instance with vault

    Returns:
        list: List of proposal dicts with rid, said, exn, datetime keys
    """
    proposals = []
    for (dt, rid), note in app.vault.notifier.noter.notes.getTopItemIter():
        route = note.pad.get('a', {}).get('r', '')
        if '/multisig/rot' in route and not note.read:
            said = note.attrs.get('d', '')
            if said:
                try:
                    exn, pathed = exchanging.cloneMessage(app.vault.hby, said)
                    if exn:
                        proposals.append({
                            'rid': rid,
                            'said': said,
                            'exn': exn,
                            'pathed': pathed,
                            'datetime': note.datetime
                        })
                except Exception as e:
                    logger.warning(f"Failed to clone multisig rotation proposal {said}: {e}")
    return proposals


class GroupMultisigInceptDoer(doing.DoDoer):
    """
    Doer for asynchronous group multisig identifier inception.

    Handles the complete group identifier creation workflow including:
    - Creating the group hab via hby.makeGroupHab()
    - Creating inception EXN message via grouping.multisigInceptExn()
    - Sending EXN to all participants via postman.send()
    - Starting Counselor escrow processing
    - Signaling completion/progress to UI
    """

    def __init__(self, app, alias, mhab, smids, rmids=None, isith=None, nsith=None,
                 wits=None, toad=0, delpre=None, signal_bridge=None, **kwargs):
        """
        Initialize the GroupMultisigInceptDoer.

        Args:
            app: Application instance with vault
            alias: Alias for the new group identifier
            mhab: Local member hab (Hab instance)
            smids: List of signing member AIDs (qb64 strings)
            rmids: Optional list of rotation member AIDs (defaults to smids)
            isith: Signing threshold (int or str)
            nsith: Next signing threshold (int or str, defaults to isith)
            wits: List of witness AIDs
            toad: Threshold of acceptable duplicity
            delpre: Optional delegator prefix for delegated group
            signal_bridge: DoerSignalBridge for UI communication
            **kwargs: Additional parameters for makeGroupHab
        """
        self.app = app
        self.hby = app.vault.hby
        self.alias = alias
        self.mhab = mhab
        self.smids = smids
        self.rmids = rmids if rmids is not None else smids
        self.isith = isith if isith is not None else len(smids)
        self.nsith = nsith if nsith is not None else self.isith
        self.wits = wits or []
        self.toad = toad
        self.delpre = delpre
        self.signal_bridge = signal_bridge
        self.kwargs = kwargs

        # Get vault components
        self.postman = app.vault.postman
        self.counselor = app.vault.counselor

        doers = [doing.doify(self.incept_do)]

        super(GroupMultisigInceptDoer, self).__init__(doers=doers)

    def incept_do(self, tymth, tock=0.0, **opts):
        """
        Generator method for group multisig identifier inception.

        Args:
            tymth: Tymist function for time management
            tock: Initial tock value

        Yields:
            tock: Current tock value for doer scheduling
        """
        # Enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        try:
            # Signal inception started
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigInceptDoer",
                    event_type="group_inception_started",
                    data={'alias': self.alias, 'smids': self.smids}
                )

            # Step 1: Create group hab
            logger.info(f"Creating group hab '{self.alias}' with smids: {self.smids}")
            ghab = self.hby.makeGroupHab(
                group=self.alias,
                mhab=self.mhab,
                smids=self.smids,
                rmids=self.rmids,
                isith=self.isith,
                nsith=self.nsith,
                wits=self.wits,
                toad=self.toad,
                delpre=self.delpre,
                version=kering.Vrsn_2_0,
                **self.kwargs
            )

            # Step 2: Get inception event (partially signed)
            icp = ghab.msgOwnInception(allowPartiallySigned=True, gvrsn=kering.Vrsn_2_0)
            serder = SerderKERI(raw=icp)

            logger.info(f"Group hab created with prefix: {ghab.pre}")

            # Step 3: Create EXN message
            exn, atc = keri_grouping.multisigInceptExn(
                hab=self.mhab,
                smids=self.smids,
                rmids=self.rmids,
                icp=icp,
                delegator=self.delpre,
                version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0
            )
            # The Create click approves this exact child; upstream Mux retains that contribution.
            self.app.vault.mbx.parser.parse(ims=bytearray(exn.raw + atc), local=True)

            logger.info(f"Created multisig inception EXN: {exn.said}")

            # Step 4: Send to all other participants
            others = [pre for pre in self.smids if pre != self.mhab.pre]
            for recpt in others:
                self.postman.send(
                    src=self.mhab.pre,
                    dest=recpt,
                    topic="multisig",
                    serder=exn,
                    attachment=atc, stream=True
                )
                logger.info(f"Sent multisig inception EXN to {recpt}")

            # Queueing is separate from transport and the group signature threshold below.
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigInceptDoer",
                    event_type="group_inception_exn_queued",
                    data={'alias': self.alias, 'pre': ghab.pre, 'recipients': others}
                )

            # Step 5: Start counselor escrow
            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Number(sn=0)
            saider = coring.Diger(qb64=serder.said)
            self.counselor.start(ghab=ghab, prefixer=prefixer, number=seqner, diger=saider)

            logger.info(f"Started counselor escrow for {ghab.pre}")

            # Signal waiting for signatures
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigInceptDoer",
                    event_type="group_inception_waiting",
                    data={'alias': self.alias, 'pre': ghab.pre}
                )

            # Step 6: Wait for completion
            while not self.counselor.complete(prefixer, seqner):
                yield self.tock

            # Step 7: Signal success
            logger.info(f"Group identifier {self.alias} ({ghab.pre}) created successfully")

            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigInceptDoer",
                    event_type="group_identifier_created",
                    data={
                        'alias': self.alias,
                        'pre': ghab.pre,
                        'success': True
                    }
                )

            self.app.vault.remove([self])
            return

        except Exception as e:
            logger.exception(f"GroupMultisigInceptDoer failed with exception: {e}")

            # Signal failure to UI
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigInceptDoer",
                    event_type="group_inception_failed",
                    data={
                        'alias': self.alias,
                        'error': str(e),
                        'success': False
                    }
                )
            self.app.vault.remove([self])
            return


class MultisigJoinDoer(doing.DoDoer):
    """
    Doer for joining an existing multisig group proposal.

    Handles:
    - Joining the group hab via hby.joinGroupHab()
    - Creating response EXN message
    - Sending response to initiator
    - Starting Counselor escrow processing
    - Signaling completion to UI
    """

    def __init__(self, app, alias, proposal_said, mhab, signal_bridge=None):
        """
        Initialize the MultisigJoinDoer.

        Args:
            app: Application instance with vault
            alias: Alias for the group identifier
            proposal_said: SAID of the proposal EXN message
            mhab: Local member hab (Hab instance)
            signal_bridge: DoerSignalBridge for UI communication
        """
        self.app = app
        self.hby = app.vault.hby
        self.alias = alias
        self.proposal_said = proposal_said
        self.mhab = mhab
        self.signal_bridge = signal_bridge

        # Get vault components
        self.postman = app.vault.postman
        self.counselor = app.vault.counselor

        doers = [doing.doify(self.join_do)]

        super(MultisigJoinDoer, self).__init__(doers=doers)

    def join_do(self, tymth, tock=0.0, **opts):
        """
        Generator method for joining a multisig group proposal.

        Args:
            tymth: Tymist function for time management
            tock: Initial tock value

        Yields:
            tock: Current tock value for doer scheduling
        """
        # Enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        try:
            # Authenticate the retained proposal before creating local group state.
            exn, oicp = inception_proposal(self.app.vault, self.proposal_said)

            # Extract proposal data
            payload = exn.ked.get('a', {})

            gid = payload.get('gid')
            smids = payload.get('smids', [])
            rmids = payload.get('rmids', smids)
            delegator = oicp.ked.get('di')

            logger.info(f"Joining group '{self.alias}' with prefix {gid}")

            # Verify local identifier is in smids
            if self.mhab.pre not in smids:
                raise ValueError(f"Local identifier {self.mhab.pre} not in proposal smids")

            # Join and sign the retained body; never reconstruct an inception from form fields.
            ghab = self.hby.joinGroupHab(
                pre=gid,
                group=self.alias,
                mhab=self.mhab,
                smids=smids,
                rmids=rmids
            )

            logger.info(f"Created group hab with prefix: {ghab.pre}")

            # Contribute our signature to the exact retained inception.
            own_icp = messagize(oicp, sigers=ghab.sign(oicp.raw, verfers=oicp.verfers),
                               gvrsn=kering.Vrsn_2_0)
            self.app.vault.mbx.parser.parse(ims=bytearray(own_icp), local=True)
            own_serder = SerderKERI(raw=own_icp)

            # Retain the approved response before queueing it for other members.
            resp_exn, resp_atc = keri_grouping.multisigInceptExn(
                hab=self.mhab,
                smids=smids,
                rmids=rmids,
                icp=own_icp,
                delegator=delegator,
                version=kering.Vrsn_2_0, gvrsn=kering.Vrsn_2_0
            )
            self.app.vault.mbx.parser.parse(ims=bytearray(resp_exn.raw + resp_atc), local=True)

            logger.info(f"Created response EXN: {resp_exn.said}")

            # Queue the response for all other signing members.
            others = [pre for pre in smids if pre != self.mhab.pre]
            for recpt in others:
                self.postman.send(
                    src=self.mhab.pre,
                    dest=recpt,
                    topic="multisig",
                    serder=resp_exn,
                    attachment=resp_atc, stream=True
                )
                logger.info(f"Sent multisig join response to {recpt}")

            # Ordinary Counselor escrow enforces the group threshold.
            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Number(sn=0)
            saider = coring.Diger(qb64=own_serder.said)
            self.counselor.start(ghab=ghab, prefixer=prefixer, number=seqner, diger=saider)

            logger.info(f"Started counselor escrow for {ghab.pre}")

            # Signal waiting
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="MultisigJoinDoer",
                    event_type="group_join_waiting",
                    data={'alias': self.alias, 'pre': ghab.pre}
                )

            # Wait for the ordinary group completion boundary.
            while not self.counselor.complete(prefixer, seqner):
                yield self.tock

            # Report completion to the UI.
            logger.info(f"Successfully joined group {self.alias} ({ghab.pre})")

            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="MultisigJoinDoer",
                    event_type="group_identifier_joined",
                    data={
                        'alias': self.alias,
                        'pre': ghab.pre,
                        'success': True
                    }
                )

            self.app.vault.remove([self])
            return

        except Exception as e:
            logger.exception(f"MultisigJoinDoer failed with exception: {e}")

            # Signal failure to UI
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="MultisigJoinDoer",
                    event_type="group_join_failed",
                    data={
                        'alias': self.alias,
                        'error': str(e),
                        'success': False
                    }
                )
            self.app.vault.remove([self])
            return


class GroupMultisigRotateDoer(doing.DoDoer):
    """
    Doer for initiating a group multisig rotation.

    Mirrors keripy GroupMultisigRotate.rotateDo. Handles:
    - Resolving member key states (verfers/ndigers)
    - Creating the rotation event via ghab.rotate()
    - Creating and sending rotation EXN to all participants
    - Starting Counselor escrow for signature collection
    - Waiting for counselor completion (cgms)
    - Post-counselor witness authentication hooks
    - Signaling progress/completion to UI
    """

    def __init__(self, app, ghab, smids=None, rmids=None, isith=None, nsith=None,
                 toad=None, cuts=None, adds=None, data=None, signal_bridge=None):
        """
        Initialize the GroupMultisigRotateDoer.

        Args:
            app: Application instance with vault
            ghab: GroupHab instance to rotate
            smids: Signing member AIDs (defaults to ghab.smids)
            rmids: Rotation member AIDs (defaults to smids)
            isith: Current signing threshold
            nsith: Next signing threshold
            toad: Witness threshold after rotation
            cuts: List of witness AIDs to remove
            adds: List of witness AIDs to add
            data: Optional list of seal dicts
            signal_bridge: DoerSignalBridge for UI communication
        """
        self.app = app
        self.hby = app.vault.hby
        self.ghab = ghab
        self.smids = smids
        self.rmids = rmids
        self.isith = isith
        self.nsith = nsith
        self.toad = toad
        self.cuts = cuts if cuts is not None else []
        self.adds = adds if adds is not None else []
        self.data = data
        self.signal_bridge = signal_bridge

        # Get vault components
        self.postman = app.vault.postman
        self.counselor = app.vault.counselor

        doers = [doing.doify(self.rotate_do)]

        super(GroupMultisigRotateDoer, self).__init__(doers=doers)

    def rotate_do(self, tymth, tock=0.0, **opts):
        """
        Generator method for group multisig rotation.

        Args:
            tymth: Tymist function for time management
            tock: Initial tock value
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        try:
            # Default smids/rmids to current group members
            if self.smids is None:
                self.smids = self.ghab.smids
            if self.rmids is None:
                self.rmids = self.smids

            # Signal rotation started
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigRotateDoer",
                    event_type="group_rotation_started",
                    data={'alias': self.ghab.name, 'pre': self.ghab.pre, 'smids': self.smids}
                )

            # Step 1: Resolve member key states
            logger.info(f"Resolving member key states for rotation of {self.ghab.name}")
            merfers, migers = resolve_member_key_states(self.hby, self.smids, self.rmids)

            # Step 2: Validate local member is in signing members
            if self.ghab.mhab.pre not in self.smids:
                raise kering.ConfigurationError(
                    f"{self.ghab.mhab.pre} not in signing members {self.smids} for this event"
                )

            # Step 3: Create rotation event
            prefixer = coring.Prefixer(qb64=self.ghab.pre)
            seqner = coring.Number(sn=self.ghab.kever.sn + 1)

            rot = self.ghab.rotate(
                isith=self.isith, nsith=self.nsith,
                toad=self.toad, cuts=list(self.cuts), adds=list(self.adds),
                data=self.data, verfers=merfers, digers=migers
            )

            rserder = SerderKERI(raw=rot)
            logger.info(f"Created group rotation event for {self.ghab.name}, sn={seqner.sn}")

            # Step 4: Create rotation EXN message
            exn, atc = keri_grouping.multisigRotateExn(
                ghab=self.ghab, smids=self.smids, rmids=self.rmids,
                rot=bytearray(rot)
            )

            # Step 5: Send to all other members
            others = list(oset(self.smids + (self.rmids or [])))
            others.remove(self.ghab.mhab.pre)

            for recpt in others:
                self.postman.send(
                    src=self.ghab.mhab.pre, dest=recpt,
                    topic="multisig", serder=exn,
                    attachment=bytearray(atc)
                )
                logger.info(f"Sent multisig rotation EXN to {recpt}")

            # Signal EXN sent
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigRotateDoer",
                    event_type="group_rotation_exn_sent",
                    data={'alias': self.ghab.name, 'pre': self.ghab.pre, 'recipients': others}
                )

            # Step 6: Start counselor escrow
            self.counselor.start(
                ghab=self.ghab, prefixer=prefixer, number=seqner,
                diger=coring.Diger(qb64=rserder.said)
            )
            logger.info(f"Started counselor escrow for rotation of {self.ghab.pre}")

            # Step 7: Wait for counselor completion. Membership changes only
            # once the rotation is accepted.
            committed = False
            while not self.counselor.complete(prefixer, seqner):
                committed = committed or self.ghab.commitAcceptedMembers(
                    rserder, smids=self.smids, rmids=self.rmids)
                yield self.tock
            if not committed:
                self.ghab.commitAcceptedMembers(rserder, smids=self.smids, rmids=self.rmids)

            # Step 8: Handle delegation if present
            if self.ghab.kever.delpre:
                yield from self.postman.sendEventToDelegator(
                    hab=self.ghab, sender=self.ghab.mhab, fn=self.ghab.kever.sn
                )

            # Step 9: Check for shared witnesses needing authentication
            shared_witnesses = get_shared_witnesses(self.ghab)
            needs_witness_auth = len(shared_witnesses) > 0

            if needs_witness_auth:
                identifier_meta_info = IdentifierMetaInfo(prefix=self.ghab.pre, auth_pending=True)
                self.app.vault.db.idm.pin(keys=(self.ghab.pre,), val=identifier_meta_info)
                logger.info(f"Set auth_pending=True for {self.ghab.pre} ({len(shared_witnesses)} shared witnesses)")

            # Step 10: Signal success
            logger.info(f"Group rotation complete for {self.ghab.name} ({self.ghab.pre})")

            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigRotateDoer",
                    event_type="group_rotation_complete",
                    data={
                        'alias': self.ghab.name,
                        'pre': self.ghab.pre,
                        'sn': self.ghab.kever.sn,
                        'success': True,
                        'shared_witnesses': shared_witnesses,
                        'needs_witness_auth': needs_witness_auth
                    }
                )

            self.app.vault.remove([self])
            return

        except Exception as e:
            logger.exception(f"GroupMultisigRotateDoer failed: {e}")

            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="GroupMultisigRotateDoer",
                    event_type="group_rotation_failed",
                    data={
                        'alias': self.ghab.name if self.ghab else None,
                        'pre': self.ghab.pre if self.ghab else None,
                        'error': str(e),
                        'success': False
                    }
                )
            self.app.vault.remove([self])
            return


class MultisigRotationJoinDoer(doing.DoDoer):
    """
    Doer for joining a group multisig rotation proposal.

    Mirrors keripy JoinDoer.rotate(). Handles:
    - Cloning the rotation proposal EXN
    - Applying the rotation event via ghab.rotate(serder=orot)
    - Committing the new members once the rotation is accepted
    - Creating and sending response EXN
    - Starting Counselor escrow
    - Waiting for counselor completion
    - Signaling progress/completion to UI
    """

    def __init__(self, app, proposal_said, mhab, group_alias=None, signal_bridge=None):
        """
        Initialize the MultisigRotationJoinDoer.

        Args:
            app: Application instance with vault
            proposal_said: SAID of the rotation proposal EXN message
            mhab: Local member hab
            group_alias: Optional alias for the group (only if group not yet known locally)
            signal_bridge: DoerSignalBridge for UI communication
        """
        self.app = app
        self.hby = app.vault.hby
        self.proposal_said = proposal_said
        self.mhab = mhab
        self.group_alias = group_alias
        self.signal_bridge = signal_bridge

        # Get vault components
        self.postman = app.vault.postman
        self.counselor = app.vault.counselor

        doers = [doing.doify(self.join_rotate_do)]

        super(MultisigRotationJoinDoer, self).__init__(doers=doers)

    def join_rotate_do(self, tymth, tock=0.0, **opts):
        """
        Generator method for joining a multisig rotation.

        Args:
            tymth: Tymist function for time management
            tock: Initial tock value
        """
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        try:
            # Step 1: Clone the rotation proposal EXN
            exn, pathed = exchanging.cloneMessage(self.hby, said=self.proposal_said)
            if exn is None:
                raise ValueError(f"Could not find rotation proposal EXN: {self.proposal_said}")

            # Step 2: Extract payload and embedded rotation event
            payload = exn.ked['a']
            smids = payload['smids']
            rmids = payload['rmids']

            embeds = exn.ked['e']
            orot = SerderKERI(sad=embeds['rot'])

            pre = orot.ked['i']
            logger.info(f"Joining group rotation for {pre}, sn={orot.sn}")

            # Step 3: Validate local member is in members
            both = list(set(smids + (rmids or [])))
            if self.mhab.pre not in both:
                raise ValueError(f"Local identifier {self.mhab.pre} not in rotation members {both}")

            # Step 4: Find or create group hab
            if pre in self.hby.habs:
                ghab = self.hby.habs[pre]
            else:
                if not self.group_alias:
                    raise ValueError(f"Group {pre} not found locally and no alias provided")
                ghab = self.hby.joinGroupHab(
                    pre, group=self.group_alias, mhab=self.mhab,
                    smids=smids, rmids=rmids
                )
                logger.info(f"Created local group hab {self.group_alias} for {pre}")

            # Step 5: Apply rotation event (joiner path - signs and processes)
            ghab.rotate(serder=orot, smids=smids, rmids=rmids)

            # Step 6: Get own partially signed event
            rot = ghab.msgOwnEvent(allowPartiallySigned=True, sn=orot.sn)

            # Step 7: Create response EXN
            resp_exn, resp_atc = keri_grouping.multisigRotateExn(
                ghab, smids=smids, rmids=rmids, rot=rot
            )

            # Step 8: Send to all other members
            others = list(oset(smids + (rmids or [])))
            others.remove(ghab.mhab.pre)

            for recpt in others:
                self.postman.send(
                    src=ghab.mhab.pre, dest=recpt,
                    topic="multisig", serder=resp_exn,
                    attachment=resp_atc
                )
                logger.info(f"Sent multisig rotation join response to {recpt}")

            # Step 9: Start counselor escrow
            serder = SerderKERI(raw=rot)
            prefixer = coring.Prefixer(qb64=ghab.pre)
            seqner = coring.Number(sn=serder.sn)

            self.counselor.start(
                ghab=ghab, prefixer=prefixer, number=seqner,
                diger=coring.Diger(qb64=serder.said)
            )
            logger.info(f"Started counselor escrow for rotation join of {ghab.pre}")

            # Signal waiting
            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="MultisigRotationJoinDoer",
                    event_type="group_rotation_join_waiting",
                    data={'alias': ghab.name, 'pre': ghab.pre}
                )

            # Step 10: Wait for counselor completion. Membership changes only
            # once the rotation is accepted.
            committed = False
            while not self.counselor.complete(prefixer, seqner):
                committed = committed or ghab.commitAcceptedMembers(orot, smids=smids, rmids=rmids)
                yield self.tock
            if not committed:
                ghab.commitAcceptedMembers(orot, smids=smids, rmids=rmids)

            # Step 11: Check for shared witnesses
            shared_witnesses = get_shared_witnesses(ghab)
            needs_witness_auth = len(shared_witnesses) > 0

            if needs_witness_auth:
                identifier_meta_info = IdentifierMetaInfo(prefix=ghab.pre, auth_pending=True)
                self.app.vault.db.idm.pin(keys=(ghab.pre,), val=identifier_meta_info)

            # Step 12: Signal success
            logger.info(f"Successfully joined group rotation for {ghab.name} ({ghab.pre})")

            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="MultisigRotationJoinDoer",
                    event_type="group_rotation_joined",
                    data={
                        'alias': ghab.name,
                        'pre': ghab.pre,
                        'sn': ghab.kever.sn,
                        'success': True,
                        'shared_witnesses': shared_witnesses,
                        'needs_witness_auth': needs_witness_auth
                    }
                )

            self.app.vault.remove([self])
            return

        except Exception as e:
            logger.exception(f"MultisigRotationJoinDoer failed: {e}")

            if self.signal_bridge:
                self.signal_bridge.emit_doer_event(
                    doer_name="MultisigRotationJoinDoer",
                    event_type="group_rotation_join_failed",
                    data={
                        'error': str(e),
                        'success': False
                    }
                )
            self.app.vault.remove([self])
            return


def get_pending_multisig_proposals(app):
    """
    Get all pending multisig inception proposals from notifier.

    Args:
        app: Application instance with vault

    Returns:
        list: List of proposal dicts with rid, said, exn, datetime keys
    """
    proposals = []
    for (dt, rid), note in app.vault.notifier.noter.notes.getTopItemIter():
        route = note.pad.get('a', {}).get('r', '')
        if '/multisig/icp' in route and not note.read:
            said = note.attrs.get('d', '')
            if said:
                try:
                    exn, pathed = exchanging.cloneMessage(app.vault.hby, said)
                    if exn:
                        proposals.append({
                            'rid': rid,
                            'said': said,
                            'exn': exn,
                            'pathed': pathed,
                            'datetime': note.datetime
                        })
                except Exception as e:
                    logger.warning(f"Failed to clone multisig proposal {said}: {e}")
    return proposals


def check_pending_multisig(app, hab):
    """
    Check if a group identifier has pending signatures.

    Args:
        app: Application instance with vault
        hab: Habery instance (identifier)

    Returns:
        bool: True if identifier has pending signatures
    """
    if not isinstance(hab, keri_habbing.GroupHab):
        return False
    try:
        pending = app.vault.counselor.pending(hab.pre)
        return pending is not None and pending[0] == 'signatures'
    except Exception as e:
        logger.warning(f"Failed to check pending multisig for {hab.pre}: {e}")
        return False


class CounselingCompletionDoer(doing.DoDoer):
    """
    Doer that resumes waiting for counselor completion on vault restart.

    Used for both inception (sn=0) and rotation (sn>0) events.
    Emits a generic 'group_counseling_complete' event when done.
    """

    def __init__(self, vault, prefixer, seqner, ghab):
        """
        Initialize the CounselingCompletionDoer.

        Args:
            vault: Vault instance
            prefixer: Prefixer for the group identifier
            seqner: Seqner for the event sequence number
            ghab: GroupHab instance
        """
        self.vault = vault
        self.counselor = self.vault.counselor
        self.prefixer = prefixer
        self.seqner = seqner
        self.ghab = ghab
        self.signal_bridge = self.vault.signals

        doers = [doing.doify(self.complete_counseling_do)]

        super(CounselingCompletionDoer, self).__init__(doers=doers)

    def complete_counseling_do(self, tymth, tock=0.0, **opts):

        # Enter context
        self.wind(tymth)
        self.tock = tock
        _ = (yield self.tock)

        # Maybe we need self.counselor.start() here?

        while not self.counselor.complete(self.prefixer, self.seqner):
            yield self.tock

        logger.info(f"Counseling complete for {self.ghab.name} ({self.ghab.pre}), sn={self.seqner.sn}")

        if self.ghab.pre not in self.vault.hby.prefixes:
            kever = self.vault.hby.kevers[self.ghab.pre]
            if len(kever.wits) == 0: # Prevents receiptor error when there are no witnesses
                self.vault.hby.prefixes.add(self.ghab.pre)

        if self.signal_bridge:
            logger.info(f"Signaling completion of counseling for {self.ghab.name}")
            data = {
                'alias': self.ghab.name,
                'pre': self.ghab.pre,
                'sn': self.seqner.sn,
                'success': True
            }

            # For rotation completions (sn > 0), include shared witness info
            if self.seqner.sn > 0:
                shared_witnesses = get_shared_witnesses(self.ghab)
                data['shared_witnesses'] = shared_witnesses
                data['needs_witness_auth'] = len(shared_witnesses) > 0

                if shared_witnesses:
                    identifier_meta_info = IdentifierMetaInfo(prefix=self.ghab.pre, auth_pending=True)
                    self.vault.db.idm.pin(keys=(self.ghab.pre,), val=identifier_meta_info)

            # Emit generic counseling completion event
            self.signal_bridge.emit_doer_event(
                doer_name="CounselingCompletionDoer",
                event_type="group_counseling_complete",
                data=data
            )

        self.vault.remove([self])
        return
