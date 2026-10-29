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

The vault shares one KERIpy graph verification context across its IPEX handlers.
Only an explicit ``True``
evaluation permits new receipt consent, inventory, or Grant signing/delivery.
An unresolved result or missing evaluation evidence uses the existing waiting
state; ``False`` refuses the action. An authenticated Grant remains retained
for inspection or refusal. Existing accepted inventory and identical receipt
recovery remain historical records, even if current evidence changes.

Building the Docs
-----------------

Build the local HTML documentation with Sphinx:

.. code-block:: bash

   uv run --locked sphinx-build -W -b html docs docs/_build/html

Plugins
-------

See :doc:`plugin-authoring` for the provider integration contract.

Registry evidence synchronization
---------------------------------

Native v2 synchronization verifies the returned CESR evidence through the vault's
existing KERIpy processors. Observer-specific freshness headers and observation-age
acceptance deadlines are not used. KRAM continues to govern protocol-message timing.
The registry worker's local polling timer schedules acquisition of newer evidence;
it does not invalidate an already accepted registry head. Changing the configured
source or reopening a vault requires a new synchronization with that source.
