Native community parity profile
===============================

This fork adds the community-service profile while preserving the adopted
Locksmith application. It is an R&D integration, not an unqualified conformance
or production-readiness claim. The original KERIpy/Dolly KLI workflows remain
independent acceptance oracles.

Source lineage
--------------

* The application and negotiation UI derive from KERI Foundation Locksmith
  PR 92, adopted at ``0c09cc03faeb04be6683c877a32869204f35aa3a`` by fast-forward.
  Original commits, authors and license are retained. No claim is made that our
  later changes were authored or endorsed by those contributors.
* ``CredentialUpdateDoer.anchor`` adapts pending-anchor selection from Kent's
  KERIpy ``NativeAuthor.anchor`` at ``9ca869f6``. Searching a locally signed seal
  locates authoring work only. Receipt collection and registry acceptance still
  authenticate that event. This prevents reopening a vault from creating a
  duplicate anchor when the original is awaiting witness quorum.
* Linked-credential fixtures explicitly use ``NI2I`` when their scenario links
  credentials without an issuer-to-issuee relation. KERIpy enforces the pinned
  ACDC default ``I2I`` for targeted far nodes; relaxing the verifier to preserve
  an invalid fixture would misrepresent that relationship. This is a local
  fixture correction, not a new wallet policy.
* The exact KERIpy dependency pin and Linux Qt test image are local build
  choices. Docker tests use copied source and named LMDB volumes. They do not
  require host database mounts or imply that a headless test proves UI parity.

Evidence and remaining gates
----------------------------

The initial installed donor baseline had 333 passes, three skips and seven
failures. The five invalid-relation fixtures and two revocation retry failures
are repaired; the focused 118 tests pass. External-service integration,
grant-specific disclosure selection, optional opening/derivation capabilities,
headless end-to-end scenarios and actual UI qualification remain separate gates.

Full-evidence service configuration
-----------------------------------

Set ``registries.profile`` to ``full-evidence`` alongside the registrar and
observer base URLs. This profile targets the upgraded KF services' external
listeners. Bootstrap their publisher/reader KELs and allowlists before running
the wallet. The older bare-TEL/admin-JSON profile remains the default for
existing deployments; it is not the qualified source-freshness profile.

``core.evidence`` borrows KERIpy's ``EvidenceProcessor`` at ``7671c088`` and
adapts signed requests and response verification from ``public_evidence.Request``.
``RegistrySyncDoer`` retains the donor Qt network/cancellation lifecycle.
``Vault`` owns one Kramer/pruner and one foreign native Rever, shared by mailbox
and observer intake. There are no application writes to accepted TEL ordinals,
anchors or heads. Legacy bare-TEL input is still preflighted before common Rever
acceptance. Full evidence retains ordinary incomplete dependencies for retry.

A full observer response must be fresh CESR, have a recent receiver observation
time, and independently verify to exactly its advertised registry head. These
are application observation facts, not proof of global wall-clock publication.
Changing endpoint or profile clears wallet freshness/publication caches.

Installed tests cover unknown-issuer KEL proof acquisition, public and blinded
updates, signed full publication, stale/future/missing metadata, mismatched heads
and retained missing dependencies. Real external binary scenarios remain a
separate qualification gate.
