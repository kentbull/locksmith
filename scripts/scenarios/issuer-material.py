"""Public artifacts and explicit local inputs for the Locksmith issuer story."""
import json
from pathlib import Path
import sys

from keri.acdc.messaging import acmSchemaDefault
from locksmith.driver.scenario import request


def issue(root, mode):
    """Issue via the running application and persist only public test artifacts.

    root owns the scenario's private control socket and ephemeral TOTP headers.
    mode selects public, blinded or derived state; no custody is exported here.
    """
    _, schema = acmSchemaDefault()
    loaded = request(root, 'issuer', {'op': 'schema', 'schema': schema, 'issuer': 'issuer'})
    auths = json.loads((root / 'private/issuer-auth.json').read_text())
    result = request(root, 'issuer', {'op': 'issue', 'alias': 'issuer',
        'schema': loaded['schema'], 'recipient': (root / 'holder.aid').read_text().strip(),
        'attributes': json.loads((root / 'attributes.json').read_text()),
        'registry_mode': mode,
        'auths': auths})
    # Expand the known schema only in this public display artifact. The actual
    # credential/proofs remain the application's authored bytes.
    display = dict(result['sad'], s=schema)
    (root / 'credential.json').write_text(json.dumps(display))
    (root / 'public.cesr').write_text(result.pop('registry_evidence'))
    (root / 'issued-update.ref').write_text(result['update'])
    result.pop('stream')
    result.pop('sad')
    print(json.dumps(result))


if __name__ == '__main__':
    issue(Path(sys.argv[1]), sys.argv[2])
