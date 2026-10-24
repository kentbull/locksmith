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
* The exact KERIpy dependency pin is an application compatibility choice.
  Composed Linux Qt images are owned by the independent experiment repository;
  headless component tests do not by themselves prove UI workflow parity.

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

Disclosure review controls
--------------------------

The response dialog lets the operator select an exact admitted grant. A later
fuller admission is listed separately and never silently enriches the earlier
selection. State refresh is optional: retain a known opening, select an
explicit event-opening file, or deliberately use provisioned local custody.
These controls neither import salts nor establish cryptographic delegation.
The normal held-material path leaves them disabled.

Offer and Grant previews apply the requested disclosure paths and selected
admission using the same application composer options as sending. A partial
Offer can already reveal values: both sending and agreement dialogs display
those values and explain that they are disclosed before agreement. Metadata-only
Offers keep their existing behavior. Separate-presenter eligibility consults the
explicit per-credential local policy; receipt alone grants no such policy.

An Offer preview is a signed disclosure of already-held content, not a current
registry-state assertion. It uses pure commitment-preserving selection and needs
no new state opening. Grant composition still requires independently checked
current registry evidence and the exact valid opening. This follows the existing
metadata-Offer/proof-bearing-Grant separation in KERIpy and the adopted PR 92
composer; the wallet no longer makes a future Grant capability prerequisite to
previewing an Offer. State-opening controls apply to Grant only.

Issuance state controls
-----------------------

The issuance dialog now exposes public state, individual blinded openings and
explicit future-opening derivation. Its small ``StatePublicationOptions`` widget
is local UI composition over the existing ``registry_authoring`` modes. Selecting
a known designated discloser binds optional custody locally; the form clearly
states that it sends no secret and creates no delegation. Anchor/signature
credentials hide these inapplicable options. The established blinded default is
preserved. Selection itself never opens custody.

Explicit issuee-bound derivation
--------------------------------

Optional ``bound_event`` on Grant composition, negotiated responses and the
opening controls select an exact accepted issuee KEL digest. It requires explicit
``derive`` and ``refresh`` for presentation. The advanced UI field appears only
for the derivation source. It does not silently substitute today's issuee head:
an existing opening may name an earlier accepted, fully witnessed event. A wrong
or unknown event fails. Per-event supplied proofs remain usable without custody.

This adapts KERIpy ``ExchangeDoer.registryOrigin`` at aef3013d and shares
``credential_disclosing.boundEvent`` from 993b5826. Original issued proofs may
supply their exact retained coordinates; vacuous bound candidates retain the
core zero/empty placeholder convention. Every resulting proof still passes
``registryProof``/``vetBound``. Inventory/revocation decoding recognizes both
existing BlindState and BoundState records rather than assuming every retained
opening has the unbound layout. These controls grant no issuance authority and
make no global wall-clock publication claim.


Bound authoring and revocation
------------------------------

Issuance and revocation also accept explicit ``bound_event``. Public state and
non-registry authentication reject that option. The authoring adapter shares the
core event lookup, then enforces the existing KLI current-issuee-head requirement
before creating a new bound update. Both individually blinded and derived modes
use ordinary registry staging and witness receipt acceptance. The UI exposes the
exact event field separately from the registry salt's designated discloser.

Revocation reuses the prior bound event if still current. If the issuee has
advanced, the operator must select its new current event; no silent unbinding or
clock-based substitute occurs. Already retained revocations retry their original
signed update. No database field or second authority state machine is introduced:
the exact original opening already carries its bound coordinates. This local
adapter follows ``NativeAuthor.update`` at aef3013d and the existing ``stage``
composition; it does not establish independent publication-time evidence.


Visible disclosure selections
-----------------------------

Disclosure field selection and the optional current-state toggle reuse the
existing ``LocksmithCheckbox`` toolkit widget. Screenshot review of the real
themed dialogs found that plain Qt checkboxes rendered labels without a clear
unchecked indicator. Reusing the existing bordered indicator makes both states
visible while retaining the same toggled signals and disclosure decisions.
This is a local UI integration correction, not a protocol requirement. The
widget and its styling already exist in the community donor ``0c09cc03``; no
new control framework or selection semantics were introduced.



Observation cache lifetime
--------------------------

Full-profile freshness is bounded by the observer's original observation time.
The wallet caches only the remaining portion of its 15-second observation-age
policy, using a monotonic deadline bound to the configured source and exact head.
Receiving a nearly expired observation does not restart a 60-second wallet cache.
The older bare-TEL profile retains its existing refresh cadence.


Offer section controls
----------------------

An operator starting an Offer can now choose an admitted view and check which
expanded committed attribute sections to reveal before agreement. Unchecked
sections remain compact commitments. With no sections checked the established
metadata-only Offer remains the default. The selection control lists only
material in the selected view; it cannot select a withheld section from another
admission. Schemas without independently committed sections retain their existing
whole-credential negotiation behavior.


Hosted issuance authorization
------------------------------

Precomputed witness authorization headers may be supplied as ``auths`` instead
of manually entered ``codes``. They retain the exact OTP generation timestamp;
replacing that timestamp can pair a previous 30-second TOTP value with the next
window and make a valid operator input fail. The hosted issuer scenario reproduced
this at 15:26:29.963 UTC before a 15:26:30 request. The worker rejects mixed inputs
and unknown witness IDs before authoring registry state. This local adapter
correction preserves the hosted provider's existing authorization contract.


Application owner and toolkit lineage
-------------------------------------

``LocksmithWindow(app=...)`` accepts an existing application owner while its
normal constructor retains ordinary launch behavior. This supports external
adapters without creating a second vault/scheduler or importing experiment code.

Disclosure selectors and the opening button reuse the existing toolkit rather
than native unstyled controls. ``FloatingLabelComboBox`` traces to Evan Asakawa's
initial Locksmith port, ``ea50b93``; our composition and live-test fixes do not
imply his authorship or endorsement. Rendering review exposed the original black
native selectors. The corrected controls retain exact-view selection semantics
and their existing real-crypto keyboard regression.



Validation and experiment ownership
-----------------------------------

Product tests remain in ``tests/``; run ``python -m pytest -q tests`` with the
installed package and its test dependencies. Tests needing KF observer must run
with that optional component installed; a missing-component skip is not a pass.

The 2026-10-21 community workflow passed its bounded KLI/v1, headless, UI, issuer,
released-peer and witness-restart gates. That historical result is not new
relocation validation. The independent ``keri-v2`` repository now owns the R&D
headless driver, real-Qt automation, Bash stories and composed qualification.
Locksmith keeps the application operations those adapters invoke.

`Pre-extraction qualification record
<https://github.com/kentbull/locksmith/blob/3933bd4199708ef9d7fb8b937d94a0c11365cd21/docs/native-parity.rst#qualified-community-workflow-2026-10-21>`_
retains its exact source pins, counts and limits. No experiment checkout is
required to run the wallet. The adopted ``full-ipex`` review baseline is unchanged.
