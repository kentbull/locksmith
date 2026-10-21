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

Exact admitted disclosures
--------------------------

``credentialing.admission`` and ``admissions`` validate per-grant consent and
signed grant/admit linkage from existing receipt records. ``credential`` and
``ipexing.grant`` accept an explicit grant selection. Defaults preserve the
original inventory view; a new fuller admission never changes an earlier view.
Deleting inventory membership still hides all views until explicit restoration.
``GrantReceipt.accepted_at`` records local consent completion, with an empty
legacy default rather than inventing a historical observation time.

This is a local application design extending the donor's existing receipts,
informed by KERIpy Wallet's exact-grant model at ``64e14e08``. No second credential
archive or automatic union of attributes is introduced. The regression exchanges
real partial/full grants, admits both, reopens the vault and presents the earlier
view. Assertions inspect parsed attributes as well as exact retained bytes;
searching plaintext in CESR-encoded bytes alone would not prove nondisclosure.

Graduation and optional opening capabilities
--------------------------------------------

``core.disclosing.material`` projects only the selected retained attribute map
with KERIpy Compactor, preserving its commitment and proof attachments. The
existing ``ipexing.start`` and ``respond`` operations now carry requested
attribute paths through Apply/Offer/Agree/Grant. A field-selecting Offer discloses
that selected view; the original whole-credential form keeps its metadata-only
Offer. Previews must show the actual selection before UI submission.

``refresh`` changes only opening evidence for already accepted current history.
Supplied CESR event openings and ``derive`` are explicit, separate choices.
Derivation borrows ``RegistryCustody`` over an optional table in the existing
Locksmith database. Ordinary held-material presentation never loads that table.
Encrypted per-registry provisioning uses the core adapter's documented R&D
plaintext owner-only file exchange, not an interoperable IPEX provisioning
message or complete key-rotation mechanism. Old-AEID or corrupt custody fails
only operations needing derivation. Bound-opening derivation controls still need
an explicit application design; supplied bound proofs use the common verifier.

``set_presenter_policy`` adds a local per-credential allowance for a known AID.
It does not claim issuer delegation, give the presenter missing data, or share
any secret. The receiving wallet must separately allow that presenter. Default
issuer/issuee restrictions remain in force when no allowance is configured.
This is a documented local application profile for the separate-discloser
scenario, not an additional KRAM rule or a new delegation protocol.

These controls adapt KERIpy's ``ExchangeDoer`` at ``a6539208`` and shared
``registryProof`` at ``8a86f16b``. The local composer/policy changes are Kent-fork
work, not attributed to the donor authors. Sixty-eight composer/policy/UI tests
pass, followed by five focused capability tests including real encrypted salt
provisioning, derived event openings and corrupt/old-key failure isolation.
Actual UI exposure and external end-to-end application qualification remain open.

Issuer state publication modes
------------------------------

``IssueCredentialDoer`` retains the donor's per-event ``blinded`` default and
adds explicit ``public`` and ``derived`` modes. Public issuance/revocation uses
native ``upd`` and never creates custody. Derived issuance provisions one
per-registry encrypted salt for the selected discloser, then uses it for later
state openings. Provisioning to another process is a separate explicit action.
``registry_authoring.stage`` adapts native KERIpy authoring at ``a6539208``;
protocol event construction and acceptance remain in KERIpy.

``IssuedCredential.registry_mode`` persists that operational choice with a
backward-compatible blinded default. Reopened revocation reuses its retained
update and anchor; missing derivation custody never silently changes the mode.
Twelve installed authoring, revocation and disclosure tests pass, including all
three modes across reopen and repeat revocation. UI mode selection and real
hosted-service authoring still require end-to-end qualification.
