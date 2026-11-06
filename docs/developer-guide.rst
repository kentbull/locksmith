Developer Guide
===============

Setup
-----

Install Python ``3.14`` and
`uv 0.9.18 <https://docs.astral.sh/uv/getting-started/installation/>`_, then run
this command from the repository root:

.. code-block:: bash

   uv sync --locked

This creates ``.venv`` with Locksmith and its development tools. The checked-in
``uv.lock`` fixes the Keripy commit and package versions used by development and
CI. ``--locked`` fails if the lockfile needs an update.

Checks
------

Run the tests, lint, and dependency checks:

.. code-block:: bash

   uv pip check
   uv run --locked ruff check src tests --select E9,F63,F7,F82
   uv run --locked pytest tests/
   uv run --locked pip-audit --local --skip-editable

CI audits dependency changes; the audit workflow can also run manually.
The audit checks published package advisories and skips Locksmith and
Git-sourced Keripy.

Dependency Updates
------------------

To adopt a newer upstream Keripy commit and its required package versions:

.. code-block:: bash

   uv lock --upgrade-package keri
   uv sync --locked

Review the lockfile diff and run the checks before committing it. uv respects
Keripy's exact dependency requirements. Routine installs retain the locked
commit even when upstream moves.

Qt Resource Regeneration
------------------------

The generated Qt resource module lives at ``src/locksmith/resources_rc.py``.

.. code-block:: bash

   uv run --locked python ./scripts/generate_qrc.py
   uv run --locked pyside6-rcc resources.qrc -o resources_rc.py
   mv resources_rc.py ./src/locksmith/

Running Locksmith
-----------------

Once the editable install is in place:

.. code-block:: bash

   uv run --locked python -m locksmith.main

For an HTTPS development service signed by a local CA, launch the normal app
with ``SSL_CERT_FILE=/absolute/path/to/ca.pem uv run --locked python -m locksmith.main``.
Locksmith adds that PEM bundle to Qt's existing trusted roots for this process;
certificate-chain and hostname verification remain enabled. An unreadable,
empty or invalid bundle fails startup with its path. This does not change OS
trust settings.

Local Development Provider
--------------------------

The normal package install also discovers the **Local Development** provider.
Its entry point is ``localdev`` and its implementation is
``locksmith.plugins.localdev.plugin.LocalDevelopmentPlugin``. It reuses the
Foundation onboarding client and pages with separate page names, per-vault
provider data and hidden onboarding identifiers.
The inherited direct-to-witness allocation controls are unavailable for this
provider: account onboarding allocates through kf-boot. Additional identifier
allocation through the account API remains unfinished.

The local provider expects kf-boot at ``http://127.0.0.1:19723``. Its explicit
``KFSurfaceConfig`` selects ``/onboarding`` and ``/account``; discovery reads
``/bootstrap/config``. Set ``LOCAL_PROVIDER_URL`` to select another local provider root URL;
this leaves the Foundation provider settings unchanged.

With ``witness-hk`` and ``watcher-hk`` checked out beside Locksmith under
``core/python`` and ``kf-boot`` under ``infra``, start the host services in one
terminal from the Locksmith repository:

.. code-block:: bash

   bash scripts/local-provider.sh

The launcher starts four witnesses, one watcher, Registrar and Observer, then
kf-boot with those backends configured. Python is the default backend. To use
TypeScript services from the local ``core/typescript/keri-ts`` checkout, first run
``deno task setup`` there once to prepare its LMDB dependency. The launcher uses
that installed dependency on subsequent restarts:


.. code-block:: bash

   LOCAL_PROVIDER_BACKEND=typescript bash scripts/local-provider.sh \
     "$HOME/.local/share/locksmith-local-provider-ts"

Use a separate state directory for each backend choice. Python dependencies use
their locked installs; TypeScript services use the normal Tufa commands through
Deno. Service identities and TLS certificates are retained across restarts.
The launcher refuses occupied ports. Set ``KERI_WORKSPACE`` if repositories live
under another KERI workspace root. The optional first argument selects service
state; the default is ``~/.local/share/locksmith-local-provider``.

To run a separate stack, set ``LOCAL_PROVIDER_PORT_OFFSET`` on the launcher and
``LOCAL_PROVIDER_URL`` on Locksmith. For example, offset ``1000`` uses
provider URL ``http://127.0.0.1:20723``. All service listeners move by that offset.

kf-boot reads ``KF_BOOT_*`` environment settings and supplies JSON bootstrap
discovery. Its existing ``Provisioner`` allocates resources through the witness
and watcher boot APIs; the wallet does not call that class directly.

In another terminal, launch Locksmith normally:

.. code-block:: bash

   uv sync --locked
   uv run --locked python -m locksmith.main

Create and open a fresh passcode-protected vault, select **Local Development**,
connect to the boot service, choose a new account alias and the **3-of-4** witness
profile, then review and start onboarding. The Local Development plugin also
activates Registrar publication and Observer query access for the permanent
account. It verifies the provider reply before saving the service URLs, identities
and public CA certificates in the vault configuration. Normal registry requests
use that account for service access and retain the original issuer or group
signatures in the evidence. Reopening retains these settings; no global TLS
trust change or manual wallet enrollment is needed.

After rotating the provider account's signing keys, open **Local Development**
and choose **Refresh credential service access**. This sends the account's
current public KEL and renews the existing service permissions. It creates no
new identity, witness allocation or rotation. Success clears prior registry
readiness so the next request uses the renewed access; failure leaves the saved
settings available for retry.

Ctrl-C in the service terminal stops only the processes it launched and preserves
their state for the next run.
Keep the services running when reopening an onboarded wallet. When deleting a
vault, the first request may queue remote cleanup; retry after cleanup finishes.
The vault is retained until kf-boot confirms account deletion.

All tests and rehearsals for this integration run directly on macOS. Real
Qt controls have completed protected vault creation, account onboarding,
witnessed rotation and watcher introduction. Reopening in a fresh wallet process
preserves the account AID, four witnesses, threshold three and KEL sequence.
The deletion dialog retains the vault while remote cleanup is pending and
clears it after a successful retry. These are automated host UI checks; manual
acceptance and the complete credential/disclosure workflow remain open.

ACDC Graph Policy
-----------------

The vault composes ordinary KERIpy IPEX handlers and its one native ``Regery``
with the existing exchanger and mailbox scheduler. New Grant signing checks the
exact selected substreams using the native graph walk, schema checks and
``EdgeVerdict`` reduction. Final signed IPEX verification remains authoritative.
New admission and outgoing use recheck the exact accepted Grant through
``Exchanger.reverifyGrant``. A valid native verdict plus authenticated ``issued``
state for every disclosed registry-backed node permits use. Retryable unknown
waits; invalid evidence refuses. Registry-free KEL/signature nodes need no
registry-state record.

Inventory, explicit receipt consent, inbox retention and saved-message delivery
remain application-owned. A saved signed Admit and its consent are historical
commitments: recovery keeps the same body, SAID, attachments and KEL anchor,
including after revocation. Recovery grants no new disclosure authority. Exchange
history preserves exact selected views; a later fuller Grant cannot hydrate an
older admission. Recorded registry observations are not a current-state verdict.

Current IPEX wire values carry one DAG: ``q.dp = [[[schema, "/", fields], ...]]``;
``[[]]`` inherits the earlier plan. Opening exchanges use native ``xip`` and do
not contain reply-only ``p``/``x`` fields. Retired flat plans are not rewritten.

The Offer form exposes only attribute material held in the selected view.
Credentials with flat attributes offer an unchecked **Reveal the whole held
attribute block** choice. Select it explicitly when the schema requires the
attribute object. Send remains disabled while the exact preview violates the
schema; the wallet never expands the disclosure automatically to satisfy it.

Registry Evidence and Existing Roots
------------------------------------

Configured acquisition sends authenticated queries and independently verifies
supporting KEL/TEL through a strict parser sharing the vault Kramer and native
Regery. A response must carry the requested registry's complete ordered TEL and
its exact accepted head. Unrelated scopes, rollback, missing KEL and incomplete
frames fail verification. Observer metadata and acquisition age are telemetry;
they do not authorize admission or replace native current evidence. The existing
finite Qt request timeout, cancellation and cleanup paths remain in use.

Event openings are native ``Blinder`` values. ``putOpening(eventSaid, blinder)``
is used only after exact accepted TEL membership; inspecting a credential never
writes an opening. Public transport includes openings only from locally issued
records explicitly marked public. Core public TEL cloning remains body-only and
never exposes arbitrary held openings or registry roots.

Optional derivation reads an existing encrypted Keeper root scoped to a local
AID and registry. Bound derivation requires an explicitly selected accepted,
fully witnessed Issuee event; it never substitutes the current KEL tip. Ordinary
held proof use and supplied openings remain independent of absent or damaged
root custody. Plaintext ``RegistryCustody`` export/import and its app table have
been removed.

Group registry issuance and consent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An accepted local group signing member can enable issuance for a schema and
choose public, per-event blinded or derived registry authentication in **Issue**.
For derived issuance, the currently elected custodian must initiate the operation.
The proposing member first submits a RIP anchor; the other members open **Activity**, review **Group registry
approval**, and explicitly approve that exact anchor. Receipt of a proposal or
closing its review contributes no signature. Issuance then proposes its BUP and
requires another explicit approval before the credential is reported issued.

The review displays the registry, TEL event and controller anchor. A blinded BUP
alone does not disclose the credential or state. The current group parent is
rechecked at the approval click; a stale review cannot authorize another event.
Group witness authorization uses the existing code fields in Issue and approval.
The ordinary elected witnesser may differ from the proposer or DH custodian.
Member consent waits while the vault is open; closing the vault stops its local
operation and does not undo already accepted protocol evidence. Reopening does
not automatically restart an interrupted issuance.

Group state updates
~~~~~~~~~~~~~~~~~~~

For a locally issued group credential, **Refresh state commitment** and
**Revoke credential** propose an exact BUP and group KEL anchor. Other members
approve that anchor through Activity's existing registry controls. Completion
requires accepted registry evidence and the ordinary group/witness thresholds.
Derived updates use the already retained group root; no fresh DH or root
generation occurs. A retry reuses the saved TEL and anchor, and an already
accepted exact update requires no new anchor. Earlier admissions retain their
original credential proofs.

Group derived issuance
~~~~~~~~~~~~~~~~~~~~~~

After the group RIP is accepted, derived issuance proposes the exact credential
Grant to the issuer members. In **Activity → Registry setup**, each contributing
member reviews the displayed Grant and approves its associated registry setup.
That one decision authorizes the member's Grant signature and contribution to
the custodian-authenticated DH query within the same scope and original deadline.
Both messages still require the ordinary group signature threshold. Receiving a
proposal without setup consent or closing an unapproved review signs nothing.
The dialog identifies the member, frozen coordinator event and elected custodian.

Only the elected custodian establishes and retains the issuer group's derivation
root. Other members contribute signatures; this does not copy the root to their
stores. The holder separately approves registry setup. Issuance then
proposes its BUP through the registry-approval controls described above. The
original Grant and deadline remain unchanged; an expired exchange cannot be
revived. The holder's **Review credential / Accept Grant** decision remains
separate from DH and issuer-group approval.

A group holder uses the same single setup decision. Each participating member
authorizes its contribution to the custodian's reply for that exact exchange;
there is no additional reply-approval click. The normal group threshold must
authenticate the reply before it leaves. Only the elected holder custodian
derives the root. Other members verify the issued Grant using public registry
evidence and the exact event opening, without receiving that root.

After setup verifies, **Review credential** offers a separate group acceptance
decision. The custodian proposes one Admit; other members review and approve
that same acknowledgment. The wallet waits for the group signature threshold
before adding the credential. Setup, receiving an Admit proposal and closing
its review do not record acceptance. The selected sender handles delivery only
after the threshold is satisfied; transport submission does not prove the
issuer received it.

Individual derived issuance now anchors a fresh RIP, retains one signed proofless
Grant and waits for explicit DH approval before issuing its BUP. The vault owns
those live operations; ordinary submission and explicit Admit remain separate.
Closing or cancelling abandons ephemeral keys and queued sends, while retained
encrypted Keeper roots and historical proofs remain. Reopening cannot resume an
unfinished agreement; begin a fresh exchange with new explicit consent. Pending
Grant bytes and private keys never enter the durable outbox.

Individual live Unblind requests use the same vault owner. The recipient explicitly
requests missing current openings for a new live presentation; the presenter must
separately approve its exact scope before the native owner replies with minimal
event proofs. Missing held proof waits under the original request deadline. Native
verification finishes the same Grant; Admit remains a separate decision, and known
revoked state still prevents application use. A later presentation starts with a
new Grant from the exact selected admitted view, never the old terminal exchange.
Closing or cancelling discards unfinished approvals and queued proofs. Unblind
does not transfer a Keeper root.

Group state openings use the same single **Request state openings** or
**Approve state openings** decision per member. Select an ordinary current
signing member as proposer; this role requires no DH root custody. The proposer
authors one v2 query or minimal opening reply. Each consenting member contributes
to those unchanged bytes, and KERIpy verifies the ordinary group threshold before
delivery. Proposal intake grants no request, proof-release or acceptance consent.
Missing proof waits within the original Grant deadline. Closing an unapproved
review signs nothing; vault closure abandons the live approval.

After opening verification, **Review credential** remains a separate exact group
Admit decision, proposed by the selected member. A presentation that needs no
setup or opening exchange allows any current signing member to propose its
first Admit. Other members review and approve that same body. Conflicting
proposals are refused; inventory changes only after the ordinary threshold.

Individual encrypted root files
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On an Issued Credentials row, choose **Export encrypted registry root**, select
the intended introduced individual recipient, then export a new CESR file. The
issuer must already hold the registry root in its unlocked encrypted Keeper.
Export reports only that an encrypted copy was written; recipient retention is
unconfirmed. Deliver this ciphertext file separately. A root permits deriving
future state openings, not issuer signing authority.

On the recipient's Received Credentials row, choose **Import encrypted registry
root**. Select the local recipient, exact received disclosure and held opening
for an accepted registry BUP. Inspect the file and review its claimed sender,
recipient, registry and reply SAID. Inspection does not authenticate or consume
the reply. **Approve and import** gives native ``RegistrySalt`` that exact scope,
then sends the unchanged reply through the vault's ordinary Parser/KRAM/Revery.
Only native successful encrypted retention reports success; an existing root or
retained reply row is insufficient. Admission and historical proofs are unchanged.

Missing accepted public evidence, an unavailable held opening, changed keys or
expired message timing refuse import. There is no acquisition, automatic retry,
new root generation or timestamp renewal. Normal operator KRAM policy applies
(the wallet's default single-key reply lag is five minutes); Exchanger's pending
Grant timeout does not govern root replies. Cancellation, refusal, completion
and vault close abandon process-local approval. Closing after successful import
does not undo the retained root. Network delivery/acknowledgment remains outside
this file workflow.

Group encrypted root files
~~~~~~~~~~~~~~~~~~~~~~~~~~

**Activity → Group registry roots** opens group provisioning without requiring a
credential inventory row. Issued and Received credential actions also open it
with the registry and an existing held opening selected where available. A new
member must already belong to the accepted group; importing a root does not join
the group or accept a credential.

Choose the local group, registry, recipient AID and encryption target member.
The recipient owns the retained root; the target member's current key decrypts
the file. An issuer group may provision a recipient; a holder group may provision
its own current members. **Prepare encrypted copy** requires an exact accepted
coordinator event whose elected member already holds the root. The default is
the displayed current event; select the appropriate accepted historical event
when needed. There is no root generation or coordinator fallback.

Preparation writes an encrypted reply and a sibling ``.proposal.cesr`` file.
Other members choose **Contribute signature**, inspect that original proposal,
select the same coordinator and transfer scope, then explicitly export their
signature on the unchanged ciphertext. Preparation alone does not establish the
group's full threshold or recipient retention.

The target member chooses **Import encrypted copy**, inspects sufficient reply
signature files for the same exact reply, and supplies an already held opening
for an accepted BUP. **Approve and import** uses KERIpy to verify the current
sender threshold, target membership, decryption and root/opening match before
encrypted Keeper retention under the group AID. A partial signature set retains
no root. Closing discards inspected files and receive approval; existing
credential admissions and public registry evidence remain unchanged.

Group presentations
~~~~~~~~~~~~~~~~~~~

On a Received Credentials row admitted by a local group, **Present from group**
selects the group's exact admitted view, the verifier and a message, then signs
this member's contribution to one Grant. ``core/group_presenting.py`` mirrors
KERIpy's group presentation: the member wraps the Grant in an ordinary
``/multisig/exn`` message, parses it through the vault's KRAM-enabled mailbox
parser and sends it to the other signing members through their mailboxes.

A partial proposal has no deadline. Activity lists it under **Group
presentations**; another member chooses **Approve contribution** only after
KERIpy and the wallet confirm that the Grant body and proofs equal that member's
own admitted view. Threshold intake assigns the accepted KRAM lifetime, which is
then the presentation's only deadline. Only the elected lead member sends: an
accepted Grant enters the outbox, while a Grant still awaiting current state
openings is delivered through the vault's live Auxiliary owner. Delivery grants
no state-opening release; each member approves openings separately.

Presenters are the credential issuee or original issuer by default. A separate
discloser requires an explicit per-credential presenter policy at both the
discloser and the verifier; root possession or custody is never presenter
authority.

The verifier separately chooses **Request state openings**. An authenticated
request enables the discloser's **Approve state openings** action in Activity.
Native Unblind selects minimal event proofs, verifies and retains the sender's
exact live Grant before the reply leaves, then independently verifies the same
Grant at the recipient. State verification still does not add the credential.
The verifier must choose **Review credential**, then **Add**.

**Cancel request** removes the selected live operation's queued or inflight
transport and abandons its proof-release authority. Vault close does the same
for unfinished operations. Failures do not renew the original deadline or revive
authority after restart.

Regression disposition
~~~~~~~~~~~~~~~~~~~~~~

The graph-use regression retains the forbidden-signer guard and complete graph
shape. Its obsolete expectation that an invalid graph becomes accepted history
is replaced by native refusal or schema escrow. All five interrupted admission
boundaries now run for signature, KEL-anchor and registry factors; witness timeout
and witness-rotation quorum tests retain their original topology and deadlines.
The admitted-view regression retains actual selection controls and reopen checks.

Observer header/age-policy cases are retired and replaced by exact scope, complete
proof, rollback and header-nonauthority checks. Registry socket timeout,
cancellation, publication head and current full-evidence observer checks remain.
The plaintext custody handoff scenario is retired;
rootless held proofs, supplied-opening independence and damaged-root isolation
remain. Existing encrypted-root fixtures cover native derivation, explicit bound
coordinates and reopen without claiming to test root provisioning.

Building the Docs
-----------------

Build the local HTML documentation with Sphinx:

.. code-block:: bash

   uv run --locked sphinx-build -W -b html docs docs/_build/html

Plugins
-------

See :doc:`plugin-authoring` for the provider integration contract.
