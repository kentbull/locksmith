Native parity change lineage
============================

This is the human review index for the additive changes from Locksmith
``0c09cc03faeb04be6683c877a32869204f35aa3a`` through
``4aebe27a7b40a9433dd1745c6fb0487aa62e7a35``. The executable qualification
snapshot is ``a2885cb01e797043b9e969d70aee981b2783ec51``; the later commit
adds docstrings only, with executable AST equality checked in every changed
Python module. Later changes require their own review.

Attribution boundaries
----------------------

The `inherited application <https://github.com/keri-foundation/locksmith/tree/0c09cc03faeb04be6683c877a32869204f35aa3a>`_
and its Git history remain intact. The native credentialing, exchange and UI
history records Evan Asakawa, including ``ce613ad`` (native V2 credentialing),
``561314e`` (workflow/recovery) and ``396a524`` (native IPEX exchange).
Those are recorded contributions, not proof that one person invented every
underlying idea. Per-line ancestry remains available through Git blame at the
pinned predecessor. Names do not transfer responsibility for our adaptations.

The `local comparison <https://github.com/kentbull/locksmith/compare/0c09cc03faeb04be6683c877a32869204f35aa3a...4aebe27a7b40a9433dd1745c6fb0487aa62e7a35>`_
records Kent Bull as Git author. These additions were designed and implemented
with Codex under Kent's direction; that metadata is not a claim of sole human
invention. Specifications define wire behavior; the UI controls, service
profiles, local policy table and operator adapters below are implementation
choices. See :doc:`native-parity` for protocol and custody boundaries.

In the following index, a class name covers its declaration and changed fields;
methods are listed separately. Existing methods absent from the list remain
inherited. Module imports and wiring are included with their containing entry.
Tests establish boundaries, not original authorship or universal conformance.

Credential and exchange domain
------------------------------

* ``core/credentialing.py``: ``admission``, ``admissions`` and ``credential``
  adapt the inherited inventory to exact grant consent. KERIpy Wallet at
  ``64e14e08`` supplied the reference model; this is a local adaptation, not a
  literal copy. ``CredentialUpdateDoer.anchor`` adapts pending-anchor lookup
  from ``NativeAuthor.anchor`` at ``9ca869f6``. The class retains the donor HIO
  lifecycle and core receipt/acceptance owners. ``IssueCredentialDoer`` and
  ``RevokeCredentialDoer``, their ``__init__`` methods, ``issue_credential_do``
  and ``revoke_do`` extend the donor operations with explicit publication mode,
  exact witness authorization, optional bound coordinates and durable retry.
  Main changes: ``9864e6d``, ``49ea1a2``, ``1403a9b``, ``f691d3d``, ``9b979cb``.
* ``core/disclosing.py``: new local ``custody``, ``material``, its nested
  ``derive_opening``, and ``select`` compose existing core capabilities.
  Compaction follows KERIpy ``ExchangeDoer`` at ``a6539208``; state proof
  assembly delegates to ``registryProof`` and encryption to ``RegistryCustody``.
  The shared ``boundEvent`` at ``993b5826`` verifies an explicitly selected
  historical issuee event. No implicit latest-event substitution is made.
  Main changes: ``927d5a9``, ``e123615``.
* ``core/registry_authoring.py``: new ``MODES``, ``stage`` and ``bound_options``
  adapt ``NativeAuthor`` at ``a6539208`` and the common ``boundEvent`` helper.
  ``Registrar.issue`` remains the random-opening author. Public and derived
  updates use the same core messaging and staging API. New bound authoring
  requires the known current issuee event; historical proof reproduction is a
  separate operation. Main changes: ``1403a9b``, ``9b979cb``.
* ``core/ipexing.py``: ``presentation_eligible``, ``_require_presenter`` and
  ``set_presenter_policy`` add explicit local presenter policy. Naming a
  presenter here creates no signed delegation or interoperable authorization.
  ``_validate_outgoing_grant``, ``_credential_evidence``, ``grant``,
  ``request_schema``, ``start``, ``respond``, ``_validate_credential`` and
  ``_finish_receipt`` adapt the inherited negotiation and consent operations
  to carry exact view/field/proof choices and validate those choices at intake
  and submission. Wire messages remain core IPEX messages. Main changes:
  ``49ea1a2``, ``927d5a9``, ``940d6f4``, ``e123615``.
* ``db/basing.py``: ``IssuedCredential`` gains explicit ``registry_mode``;
  ``GrantReceipt`` gains local ``accepted_at``. Existing records retain their
  legacy defaults. ``LocksmithBaser`` and ``reopen`` add local presenter-policy
  and encrypted-custody tables. They do not become protocol acceptance stores.
  Main changes: ``49ea1a2``, ``927d5a9``, ``1403a9b``.

Evidence lifecycle
------------------

* ``core/evidence.py``: new ``processor``, ``receive``, ``remaining`` and
  ``sync`` adapt KERIpy ``EvidenceProcessor`` at ``7671c088`` and signed
  ``public_evidence.Request``. They preserve one vault-owned verification
  context. Freshness is a receiver observation with its original deadline,
  not a second KRAM rule or a new deadline upon receipt. Main changes:
  ``6781787``, ``31b8684``.
* ``core/registries.py``: ``_events`` and ``ingest`` retain legacy framing
  validation but delegate all accepted-state writes to the common Rever.
  ``RegistrySyncDoer`` and ``__init__``, ``recur``, ``_open``, ``_request`` and
  ``sync_do`` adapt the donor Qt network operation to full evidence. Response
  limits, timeout, redirect refusal and cleanup remain explicit. Its existing
  ``Timeout`` and ``MaxResponse`` are operational limits, not protocol constants.
  ``RegistryEvidenceDoer`` and ``__init__``, ``_configure``, ``ensure``,
  ``_discover`` and ``sync_do`` preserve independent polling, cancel obsolete
  workers and retain exact source/head deadlines. Main changes: ``6781787``,
  ``31b8684``. Additional contract documentation is in ``4aebe27``.
* ``core/indirecting.py``: ``MailboxDirector``, ``__init__`` and ``escrowDo``
  adapt the inherited mailbox owner to the shared native evidence context.
  ``core/vaulting.py``: ``Vault`` and ``__init__`` compose one Kramer/pruner
  and foreign Rever, sharing them with observer intake. No additional accepted
  state writer or second vault lifecycle is introduced. Change: ``6781787``.

Application controls
--------------------

The inherited dialogs, widget toolkit and navigation remain community work.
The following selectors and previews are local additions/adaptations; they do
not define a standard ACDC wallet interface.

* ``credentials/disclosure.py``: new ``DisclosureOptions`` and ``__init__``,
  ``select``, ``_update``, ``_choose``, ``selection`` expose exact admission,
  retained/supplied/derived state proof and optional issuee-event selection.
  ``DisclosureFields`` and ``__init__``, ``select``, ``paths`` expose held
  attribute paths. Existing styled fields/buttons are reused. Changes:
  ``940d6f4``, ``c82b7ed``, ``871c4a8``, ``e123615``.
* ``credentials/activity.py``: ``ExchangeResponseDialog``, its explanatory
  ``Help`` entries, ``__init__``, ``_select_response``, ``_preview``,
  ``_show_offer``, ``_show_credential`` and ``_send`` adapt the donor response
  dialog. Offer disclosures and Grant proof refresh have distinct controls;
  preview uses the same projection as submission. Change: ``940d6f4``.
* ``credentials/start.py``: ``StartExchangeDialog``, ``__init__``,
  ``_select_sender`` and ``_send`` adapt the inherited Apply/Offer dialog to
  exact grant selection and selected held fields. Changes: ``940d6f4``,
  ``c82b7ed``. ``credentials/presentation.py.disclosed_credentials`` shares
  the domain projection for previews rather than reconstructing another view.
* ``credentials/issued/state_options.py``: new ``StatePublicationOptions``
  and ``__init__``, ``set_registry``, ``_refresh``, ``selection`` expose
  public/random/derived publication and optional exact issuee event. This is
  an explicit issuer capability choice. ``issued/issue.py`` adapts
  ``IssueCredentialDialog``, ``__init__``, ``_update_authentication_help`` and
  ``_complete_issuance`` to pass those controls to the existing doer.
  Changes: ``9f14ace``, ``9b979cb``.
* ``credentials/issued/revoke.py``: ``RevokeCredentialDialog``, ``__init__``
  and ``_revoke`` add current issuee-event selection to the inherited confirmation
  and OTP flow. Change: ``9b979cb``. ``ui/window.py``: ``LocksmithWindow`` and
  ``__init__`` accept an existing application owner so live UI qualification
  does not create another vault/scheduler. Change: ``871c4a8``.

Driver and qualification adapters
---------------------------------

These are new local R&D infrastructure, not imported community protocol code.

* ``driver/__main__.py.main`` is the operator entry point.
  ``driver/runtime.py`` contains ``MAX_REQUEST``, ``Intake``/``__init__``/
  ``on_post`` (``on_put`` aliases the same intake), ``LocalControl``/
  ``__init__``/``_connect``/``_read``/``_advance``/``_reply``/``_disconnect``/
  ``close``, and ``open_runtime``. They compose the existing Vault and QtTask,
  queue ordinary CESR into mailbox processing and accept one private local
  command at a time. Their cleanup follows the donor vault-open lifecycle.
  Change: ``024604c``.
* ``driver/operations.py.execute`` calls the same domain operations used by
  UI controls. Its optional schema/contact/policy configuration is operator
  setup, never injected accepted protocol state. ``driver/authoring.py.issue``
  and its nested ``completed`` callback drive the real IssueCredentialDoer and
  await its matching result. Changes: ``024604c``, ``3c2d489``.
* ``driver/scenario.py.request`` and ``main`` adapt existing KLI scenario
  arguments to those local application operations. They do not launch KLI as
  a substitute for Locksmith actors. Change: ``929bbd4``.
* ``scripts/scenarios/ui_runtime.py`` and ``ui_issuance.py`` use real Qt widgets
  and QTest events, including the existing Review/Accept dialogs and new
  selectors. They capture public controls only. Bootstrap, service publication
  and final issuer-to-holder Grant may use application operations; those are
  explicitly separate from UI coverage. Change: ``871c4a8``.
* Scenario shell files adapt the original six KERIpy/Dolly stories; issuer
  stories extend them through Locksmith authoring. Dockerfiles copy source and
  install packages, while named volumes own database state. No host LMDB bind
  mount is used. ``check-sources.py``, ``artifacts.py`` and
  ``qualify-community.sh`` are local clean-source/pin/wheel qualification
  guards. Change: ``a2885cb``.

Test and review evidence
------------------------

Original community tests remain present. The changed/new tests are local
boundary assertions using real signed evidence and application operations:
exact partial/full admissions, unsupported/wrong-event opening refusal,
corrupt or old-key custody isolation, bound historical proof versus current
bound authoring, stale observation, schema relation fixtures, UI selection
and cancellation/retry. The five inherited graph fixtures were corrected to
explicit ``NI2I``; the verifier's default ``I2I`` was not relaxed.

A source audit compared every current Python class/function/method, including
nested functions, against the pinned donor. Changed production symbols are
indexed above; the docstring pass also covered the surrounding changed lifecycle
methods. Presence alone is not a quality claim: descriptions were checked
against ownership, inputs, outputs and failure paths. Fixed source SHAs and
scenario manifests separately establish which artifacts actually ran.
