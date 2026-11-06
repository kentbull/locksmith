Local registry services
=======================

Normal Local Development onboarding uses ``scripts/local-provider.sh``, which
starts Registrar and Observer before kf-boot and activates wallet access through
the provider. Select ``LOCAL_PROVIDER_BACKEND=python`` or ``typescript`` on that
launcher, or select Registrar and Observer separately with
``LOCAL_PROVIDER_REGISTRAR_BACKEND`` and ``LOCAL_PROVIDER_OBSERVER_BACKEND``. The wallet verifies and saves signed service settings, including the
public CA, during onboarding. See :doc:`developer-guide` for that complete path.

The standalone ``scripts/local-registries.sh STATE_DIR [CONFIG_JSON]`` command is
for independently operated services. With no configuration file it starts with
no wallet roles, ready for provider enrollment. An explicit file grants operator-managed readers on either backend. A Python
Registrar also supports static publishers; a TypeScript Registrar uses provider
enrollment for publishers, so its ``publishers`` array must be empty. The state
directory records ``registrar=… observer=…`` in its ``topology`` file and refuses
a different selection or retained state without that file. Do not run
it on ports already owned by the complete provider launcher.

Export introductions
--------------------

In each participating wallet, use the identifier's **Share** action to export its
actual public introduction. Put the files beside a small configuration file:

.. code-block:: json

   {
     "publishers": ["issuer.cesr"],
     "readers": ["issuer.cesr", "holder.cesr", "verifier.cesr"]
   }

For a Dolly service using TypeScript infrastructure, export its actual public
introduction and use ``{"publishers": [], "readers": ["dolly.cesr"]}``. Pass the
file as the second argument to the complete provider launcher:

.. code-block:: bash

   LOCAL_PROVIDER_BACKEND=typescript bash scripts/local-provider.sh \
     "$HOME/.local/share/locksmith-local-provider-ts" /absolute/path/to/participants.json

Dolly keeps its own keys and signs Observer queries as its existing service AID.
Configured reader permission survives deletion of a provider-managed account
with the same AID. The Observer still verifies each query and its KERI evidence.

Paths are relative to that JSON file. Publishers may submit registry evidence;
readers may query Observer. Both arrays are required; either may be empty. Only explicitly selected
identifiers receive those roles. The helper verifies signed public KEL support
with the v2 KERI/ACDC processors and omits endpoint replies from service bootstrap.
It refuses incomplete or invalid key evidence. Export fresh introductions after
key changes; stop the registry launcher, update the files/config and restart it.
Changing an allowlist does not remove previously accepted public evidence.

Start on macOS
--------------

The direct ``core/python/kf-registrar`` and ``core/python/kf-observer`` checkouts
must be installed beside Locksmith for their Python services; TypeScript services
use ``core/typescript/keri-ts`` and the bootstrap helper from ``infra/kf-boot``. Their locked dependencies require Python
3.14 and libsodium. ``KERI_WORKSPACE`` may select another workspace root.

.. code-block:: bash

   bash scripts/local-registries.sh \
     "$HOME/.local/share/locksmith-local-registries" \
     /absolute/path/to/participants.json

The launcher runs ``uv sync --locked --extra dev --python 3.14`` only for the
selected Python services. Its bootstrap helper needs only KERIpy: it runs from the
Python Registrar, else the Python Observer, else the ``infra/kf-boot`` install, so
TypeScript Registrar and Observer need neither Python service checkout. It
refuses occupied ports and waits at most 15 seconds for startup health. It binds
both services to loopback: Registrar public HTTPS on port 19932 and private HTTP
administration on port 19931; Observer public HTTPS on port 19942 and private HTTP
administration on port 19941. Preflight and startup health checks cover all four
ports. TLS credentials apply to the public listeners; the private enrollment APIs
use HTTP on loopback only. Ctrl-C stops only its own children. A child failure also stops
the other child. Logs, public bootstrap and service credentials remain in the
selected state directory. Restart with the same directory to reuse the identities.

The encrypted service stores use a stable, directory-derived ``--base`` beneath
the normal KERI data root; the state directory is not a database-root override.
Keep ``service-passcode`` with those stores. It and the generated TLS private keys
are owner-readable only. Do not delete or replace retained private files while
keeping their corresponding service state. No private key or passcode is printed.

Connect the wallets
-------------------

In each participating wallet's **Settings → Credential status services**, save:

* Registrar publication URL: ``https://localhost:19932`` for publishers.
* Observer URL: ``https://localhost:19942`` for readers. Update saved HTTP URLs
  from earlier local runs.

Registrar and Observer use an isolated, persistent certificate authority and a separate
CA-signed localhost server certificate with a DNS SAN. The authority certificate
is ``ca.pem``; it permits certificate signing and carries no server-authentication
restriction. The server leaf is ``server-cert.pem`` with ``CA:FALSE`` and server
authentication enabled. Their private keys are ``ca-key.pem`` and
``server-key.pem``. All four files are retained and reused; a partial set refuses
startup. Existing single-certificate trial directories require a fresh state
directory or restoration of a complete matching CA/server set.

The CA lasts 3650 days and the server leaf 365 days. Startup refuses either
certificate with less than 24 hours remaining; certificates are not renewed
automatically. Stop these services and restore or reissue valid certificates with
their matching retained keys before restarting. Older trial leaves issued for
3650 days must also be reissued with a 365-day lifetime for the macOS Qt client.
Preserve ``service-passcode`` and the service identities during certificate work;
if the CA changes, configure its replacement ``ca.pem`` in the wallets.

Trust ``ca.pem`` through the normal application's explicit development CA support
before HTTPS publication or queries. For the example state directory, launch the normal
application with:

.. code-block:: bash

   SSL_CERT_FILE="$HOME/.local/share/locksmith-local-registries/ca.pem" \
     uv run --locked python -m locksmith.main

The launcher does not change system trust or disable certificate/hostname
verification. Observer uses the same explicit CA for its HTTPS Registrar pulls
and serves wallet and Dolly queries over HTTPS. In Dolly's JSON policy, configure
``observer`` with ``url`` set to ``https://localhost:19942/`` and ``cafilepath``
set to the absolute path of this state directory's ``ca.pem``. Dolly also needs
its public introduction included in ``readers``; TLS trust alone does not grant
query permission.

Health reports listener availability. Successful publication requires acceptance
of the exact submitted registry head. Observer independently polls Registrar and
verifies public KEL/TEL; an Observer query reads its accepted cache and does not
force an immediate pull or establish globally current credential state. Private
registry roots remain in the wallets. Blinded event openings are separate from
this public registry-history transport.
