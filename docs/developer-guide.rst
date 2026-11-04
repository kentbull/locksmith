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
``/bootstrap/config``. To change this development endpoint, edit the local
plugin's configuration rather than the Foundation provider's defaults.

With ``witness-hk`` and ``watcher-hk`` checked out beside Locksmith under
``core/python`` and ``kf-boot`` under ``infra``, start the host services in one
terminal from the Locksmith repository:

.. code-block:: bash

   bash scripts/local-provider.sh

The launcher installs each service's locked dependencies, writes its KERI JSON
endpoint configuration, and starts four witnesses, one watcher service, and
kf-boot. It refuses occupied ports. Set ``KERI_WORKSPACE`` if these repositories
live under a different KERI workspace root. An optional first argument selects
the service state directory; the default is
``~/.local/share/locksmith-local-provider``. The launcher prints log locations
and the isolated base used by service index databases in the normal KERI root.

kf-boot reads ``KF_BOOT_*`` environment settings and supplies JSON bootstrap
discovery. Its existing ``Provisioner`` allocates resources through the witness
and watcher boot APIs; the wallet does not call that class directly.

In another terminal, launch Locksmith normally:

.. code-block:: bash

   uv sync --locked
   uv run --locked python -m locksmith.main

Create and open a fresh passcode-protected vault, select **Local Development**,
connect to the boot service, choose a new account alias and the **3-of-4** witness
profile, then review and start onboarding. Ctrl-C in the service terminal stops
only the processes it launched and preserves their state for the next run.
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
does not undo the retained root. Groups and network delivery/acknowledgment are
outside this file workflow.

Signed presentation files
~~~~~~~~~~~~~~~~~~~~~~~~~

On a Received Credentials row, **Signed presentation files** prepares a new
Grant from the selected exact admission, held disclosure, verifier and message.
The file contains signed disclosed credential material, not encrypted custody.
Preparation retains the authenticated native accepted/pending Grant and displays
its original deadline. It neither registers a preliminary KRAM conversation nor
authorizes delivery, state-opening responses or Admit. Newer accepted registry
evidence may leave the selected held proof retryably unknown; preparation never
refreshes that proof or hydrates it from another admission.

The independent issuer chooses **Endorse presentation file…** in Activity,
inspects the claimed discloser/verifier and every disclosed node, then explicitly
endorses and exports the same Grant. Every selected registry-backed node must
belong to that local individual issuer. Inspection authenticates nothing; native
verification is required before exporting added issuer authentication. The
temporary selected-file allowance does not authorize third-party mailbox Grants.

Back in the discloser's dialog, choose **Resume prepared presentation**, select
the existing local preparation and its original admission/options, inspect the
endorsed file, then register it locally. Resume permits authentication additions
only: body, nested proofs, SAID and deadline remain unchanged. Ordinary enabled,
nonexempt KRAM must actually accept the final conversation; a native presentation
context alone is insufficient. Existing accepted registration is refused rather
than retried. Sending that registered Grant is a separate action.

The existing vault policy is selected before creation (pending lifetime 300
seconds and default single-key KRAM lag five minutes); operator configuration
remains authoritative. Nothing renews the original timestamp or deadline.
Closing clears inspected files, not signatures already exported. File creation
and registration never imply delivery, opening-release approval or Admit.

Live delivery of an endorsed presentation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After registration, **Deliver selected registered Grant** explicitly sends that
same Grant through the vault's live Auxiliary owner. It preserves the exact
signed body, proofs and original deadline; pending Grants never enter the
accepted-message outbox. Mailbox HTTP success means submission, not recipient
verification or acceptance. The Activity state-opening view shows progress and
the original local deadline.

The verifier separately chooses **Request state openings**. An authenticated
request enables the discloser's **Approve state openings** action in Activity;
delivery consent alone cannot release proofs. Native Unblind selects minimal
event proofs, verifies and retains the sender's exact live Grant before the
reply leaves, then independently verifies the same Grant at the recipient.
Authenticated revocation replies are still delivered; protocol completion does
not establish issued state. The verifier displays its refusal and cannot Add.
Encrypted registry roots stay in the discloser's Keeper. Only complete native
issuer-endorsed scope authorizes a separate discloser; root possession and local
presenter policy are not substitutes for that authority.

State verification still does not add the credential. The verifier must choose
**Review credential**, then **Add**. Current issued-state policy is rechecked at
that decision; revoked evidence refuses use. The sender reports recipient Admit
only after actual native verification of the exact returned signed response.
Prior admissions keep their original proofs.

**Cancel request** removes the selected live operation's queued/inflight
transport and abandons its proof-release authority. Vault close does the same
for unfinished operations. Closing the file dialog leaves explicitly authorized
delivery under Activity's control. Already delivered bytes and accepted history
remain. Failures do not silently retry, renew the original deadline or revive
authority after restart. Groups remain outside this wallet workflow.

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
