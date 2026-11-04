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
