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

Private operator driver
-----------------------

``python -m locksmith.driver run --name NAME --base BASE --alias ALIAS
--socket PRIVATE_DIR/operator.sock --port PORT`` opens one initialized vault,
its actual application, QtTask, mailbox parser and durable IPEX outbox. The
passcode is read from ``KLI_KEYSTORE_PASSCODE``. Use an owner-only directory for
the Unix socket. A second operator request is refused while one is running.

``python -m locksmith.driver call --socket PRIVATE_DIR/operator.sock`` reads one
JSON object from stdin and returns one JSON outcome. For example,
``{"op": "status"}`` checks readiness. Domain actions include schema loading,
registry-service configuration/query, inventory/inspection, Apply/Offer/Agree/
Grant/Admit, explicit presenter policy, and optional custody import/opening.
They call the same application operations as the dialogs. No KLI subprocess or
alternate protocol composer is used. The driver is a local R&D adapter, not an
interoperable administration or salt-provisioning API.

The HTTP listener accepts bounded CESR with POST or PUT at ``/`` or ``/ingest``.
A 202 response means queued for the existing mailbox parser, never user consent.
Likewise ``submitted`` means outbox transport completion; scenarios must inspect
receiver acceptance and Dolly hooks separately. Disconnect cancels the local
wait while already authorized outbox work remains durable. Shutdown closes
operator work before the application closes its vault and dependent stores.

This adapter follows the existing vault-open/QtTask lifecycle. Its socket access
uses `Qt QLocalServer UserAccessOption
<https://doc.qt.io/qtforpython-6/PySide6/QtNetwork/QLocalServer.html>`_ plus the
private parent directory; this local mechanism adds no KERI authorization rule.

Full-profile freshness is bounded by the observer's original observation time.
The wallet caches only the remaining portion of its 15-second observation-age
policy, using a monotonic deadline bound to the configured source and exact head.
Receiving a nearly expired observation does not restart a 60-second wallet cache.
The older bare-TEL profile retains its existing refresh cadence.

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

Community scenario adapter
--------------------------

The existing six separate KERIpy Bash stories accept
``SCENARIO_WALLET_PROFILE=locksmith``. The explicit test adapter translates holder
and designated-presenter commands into private application requests, starts one
vault per actor, and uses signed controller endpoints for real outbox delivery.
Issuer commands remain KLI in this profile; that is recorded in its manifest and
must not be reported as Locksmith issuer end-to-end coverage. Individual issuer
application doers have separate tests. The ordinary KLI profile remains intact.

The adapter waits for queued input to pass protocol verification before a reply,
exports only public proof artifacts, and enumerates each admitted view separately.
A withheld field may fail earlier in Locksmith's Compactor than in KLI's protocol
verification; both scenarios require refusal and no additional Dolly hook.
``scripts/scenarios/Dockerfile`` composes installed actual component wheels on
copied Linux source. Its current default manifest is deliberately marked as a
development build; final clean-artifact qualification remains a separate gate.

An operator starting an Offer can now choose an admitted view and check which
expanded committed attribute sections to reveal before agreement. Unchecked
sections remain compact commitments. With no sections checked the established
metadata-only Offer remains the default. The selection control lists only
material in the selected view; it cannot select a withheld section from another
admission. Schemas without independently committed sections retain their existing
whole-credential negotiation behavior.

Explicit operator issuance
--------------------------

The private driver accepts ``schema`` with an optional local ``issuer`` alias,
matching the UI schema-load issuer policy. ``issue`` invokes the existing
``IssueCredentialDoer`` through the vault scheduler; it requires that same issuer
policy and takes recipient, attributes and optional authentication, state mode,
witness codes and designated derivation discloser. Public, event-blinded and
explicit derived modes retain their existing application semantics. The driver
returns public credential/proof metadata only after the worker's normal success
signal. Cancellation removes the worker and preserves signed authoring records.
It does not invoke KLI or synthesize accepted state.

``driver.authoring.issue`` is local orchestration around the existing worker
and signal lifecycle, adapted from ``IssueCredentialDialog._complete_issuance``
at c82b7ed. The schema policy assignment follows ``LoadSchemaDoer`` at that
revision. These are operational adapters, not new protocol or delegation rules.

Precomputed witness authorization headers may be supplied as ``auths`` instead
of manually entered ``codes``. They retain the exact OTP generation timestamp;
replacing that timestamp can pair a previous 30-second TOTP value with the next
window and make a valid operator input fail. The hosted issuer scenario reproduced
this at 15:26:29.963 UTC before a 15:26:30 request. The worker rejects mixed inputs
and unknown witness IDs before authoring registry state. This local adapter
correction preserves the hosted provider's existing authorization contract.

Issuance state controls
-----------------------

The issuance dialog now exposes public state, individual blinded openings and
explicit future-opening derivation. Its small ``StatePublicationOptions`` widget
is local UI composition over the existing ``registry_authoring`` modes. Selecting
a known designated discloser binds optional custody locally; the form clearly
states that it sends no secret and creates no delegation. Anchor/signature
credentials hide these inapplicable options. The established blinded default is
preserved. Selection itself never opens custody.

Dedicated application-issuer story
----------------------------------

``scripts/scenarios/issuer-through-holder.sh`` adds issuer coverage without
replacing the six role-specific stories. Run it in ``locksmith:scenarios`` with
Linux named volumes at ``/tmp`` and ``/usr/local/var``; set
``SCENARIO_REGISTRY_MODE`` to ``public`` (default), ``blinded`` or ``derived``.
The image must include core b6ffa21a and Dolly 4dd76e8 or later. Identity/provider
bootstrap and the initial signed registrar publication use the existing KLI
harness. Credential issuance and the initial Grant use Locksmith's persistent
application; holder admission and both negotiated presentations do too. The
issuer stops before onward presentation. All three state modes pass with actual
KF services, hosted witness processes, and two Dolly hooks. Exact earlier-view
and hook hashes remain unchanged after fuller disclosure.

``issuer-material.py`` is a local test adapter for public artifacts and explicit
private operator inputs; it calls the application driver and never inserts
accepted protocol rows. The scenario explicitly loads Dolly's pinned upstream
ACM schema because the issuer references it by digest. The original six scenarios
remain unchanged and independently useful. These are development-image results;
final clean source/wheel manifests and the live UI pass remain open.

The driver now respects the application's existing bounded outbox retry policy.
A freshness check can expire between composition and dispatch. That transient
failure leaves an authorized retry in the ordinary outbox; the driver waits for
submission or its own deadline instead of treating the first retryable status as
terminal. Blocked policy failures and exhausted send attempts still fail.

Live controls and public UI evidence
------------------------------------

``SCENARIO_LOCKSMITH_UI=1`` selects ``scripts/scenarios/ui_runtime.py`` in the
community scenario image. This local qualification adapter opens the real
``LocksmithWindow`` over the driver's already open application owner, navigates
Credentials/Activity, activates row Review buttons, selects an exact admission
and optional opening source, and submits through the ordinary dialogs. The
window's optional ``app`` parameter preserves one vault/scheduler owner; its
normal constructor remains unchanged for regular launches. No protocol messages
or accepted-state rows are constructed by the UI adapter. Setup, provisioning,
direct Grants and negative driver commands are explicitly outside its UI claim.

The supplied-opening path uses the real file picker. Qt's modal activation must
run on its event queue after the cooperative driver yields; nested generator
execution is not a valid substitute. Dialogs retain their normal animated close
lifecycle. ``ui/*/actions.jsonl`` identifies actual controls and delivered actions;
PNG captures contain public credential/proof views only. No authentication panel
or custody material is captured. Ordinary scenario assertions still verify Dolly
hooks and exact earlier disclosures independently of UI labels.

``scripts/scenarios/issuer-ui.sh`` is an additional dedicated issuance gate. It
uses Dolly's pinned ``entitlement-v2`` fixture, the actual Issue Credential form,
manual hosted-witness OTP fields, real holder admission and one onward Dolly hook.
``SCENARIO_REGISTRY_MODE`` selects the issuance mode. Recipient naming is explicit
local address-book bootstrap over an already verified KEL; contact onboarding is
not claimed as UI coverage. ``ui_issuance.py`` never records private OTP inputs.
The six graduated stories remain distinct and retain their original assertions.

The UI harness, owner injection and capability controls are local R&D choices.
Disclosure selectors and the opening button reuse the existing toolkit rather
than native unstyled controls. ``FloatingLabelComboBox`` traces to Evan Asakawa's
initial Locksmith port, ``ea50b93``; our composition and live-test fixes do not
imply his authorship or endorsement. Rendering review exposed the original black
native selectors. The corrected controls retain exact-view selection semantics
and their existing real-crypto keyboard regression.


Explicit issuee-bound derivation
--------------------------------

Optional ``bound_event`` on Grant composition, negotiated responses and the
opening driver selects an exact accepted issuee KEL digest. It requires explicit
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


Clean published-source qualification
------------------------------------

``scripts/scenarios/qualify-community.sh`` takes clean source locations through
``KERI_SOURCE``, ``DOLLY_SOURCE``, ``REGISTRAR_SOURCE``, ``OBSERVER_SOURCE`` and
``WITNESS_SOURCE``; its own checkout supplies Locksmith. Use fresh clones at
explicit commits. ``check-sources.py`` refuses dirty inputs, verifies publication
on each authorized Kent branch, and requires every package to pin the same core
commit. The check repeats after image construction. It never pushes or merges.

The runner builds the core, wallet and community images from those inputs, checks
installed wheel requirements/revisions, runs component suites and the original
KLI/v1 qualification, then runs six separate headless and six real-UI stories,
three issuer state modes in each launcher, actual released hosted peers, and the
hosted quorum/restart case. Linux state uses named volumes only. Set
``QUALIFICATION_RUN`` and ``QUALIFICATION_OUTPUT`` for an explicit volume prefix
and external log directory. A failed command stops the run and leaves evidence.
The terminal success line is emitted only after every command exits successfully.

``artifacts.py`` records the six wheel hashes, installed package locations and
requirements, source revisions and clean-build status. Development defaults stay
unqualified. This local build contract replaces the earlier hard-coded dirty
manifest; it is not a signed supply-chain attestation or proof of bit-reproducible
wheel archives. Screenshots and protocol assertions remain separate evidence.

Complete component test environment
-----------------------------------

The final wallet suite runs in the composed scenario image, with the actual
observer installed. The wallet-only image skips three optional observer ingress
cases; their absence is not a pass. Running them exposed the retained bare-TEL
endpoint's missing KEL PUT support, repaired in KF observer ``4d15b8e``. These
cases use 0, 4 and 32 rotations and real Qt transport. This older API profile is
still native v2, so its signed queries continue to use KRAM. It is distinct from
the full-evidence profile's bootstrap and freshness contract.
