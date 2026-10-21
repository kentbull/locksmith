"""Record installed qualification artifacts without inventing source cleanliness.

The host runner verifies each Git checkout and exact common-core requirement
before invoking the build. Development builds remain explicitly unqualified.
"""
from email.parser import Parser
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
from zipfile import ZipFile

COMPONENTS = ('keripy', 'dolly', 'registrar', 'observer', 'witness', 'locksmith')
PACKAGES = ('keri', 'dolly', 'kf-registrar', 'kf-observer', 'witopnet', 'locksmith')


def manifest(root):
    """Write wheel hashes, installed requirements and caller-verified revisions.

    root is the image artifact directory. Qualified builds require immutable
    40-character revisions and identical KERIpy Git requirements in all five
    consumers. This checks package metadata, not merely matching version labels.
    """
    clean = os.environ.get('QUALIFIED_CLEAN') == '1'
    value = {'qualified_clean_build': clean, 'packages': {}, 'wheels': {}}
    core = os.environ['SCENARIO_KERIPY_REVISION']
    for component, package in zip(COMPONENTS, PACKAGES, strict=True):
        revision = os.environ['SCENARIO_' + component.upper() + '_REVISION']
        if clean and (len(revision) != 40 or any(char not in '0123456789abcdef' for char in revision)):
            raise ValueError('Qualified source revision must be an immutable Git SHA')
        value[component + '_revision'] = revision
        value[component + '_worktree_dirty'] = not clean
        dist = metadata.distribution(package)
        requirements = dist.requires or []
        if clean and package != 'keri':
            pins = [item for item in requirements if item.lower().startswith('keri@')
                    or item.lower().startswith('keri @')]
            if len(pins) != 1 or ('keripy.git@' + core) not in pins[0]:
                raise ValueError(f'{package} does not require the qualified common core')
        value['packages'][package] = {'version': dist.version,
            'location': str(dist.locate_file('')), 'requirements': requirements}
    wheel_packages = set()
    for wheel in root.glob('*.whl'):
        with ZipFile(wheel) as archive:
            entries = [name for name in archive.namelist() if name.endswith('.dist-info/METADATA')]
            if len(entries) != 1:
                raise ValueError('Ambiguous wheel metadata')
            package = Parser().parsestr(archive.read(entries[0]).decode())['Name'].lower()
        value['wheels'][wheel.name] = hashlib.sha256(wheel.read_bytes()).hexdigest()
        if package not in PACKAGES or package in wheel_packages:
            raise ValueError(f'Unexpected or duplicate wheel: {package}')
        wheel_packages.add(package)
    if wheel_packages != set(PACKAGES):
        raise ValueError('Qualification requires exactly six component wheels')
    (root / 'manifest.json').write_text(json.dumps(value, indent=2) + '\n')


if __name__ == '__main__':
    manifest(Path('/artifacts'))
