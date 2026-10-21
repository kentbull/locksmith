"""Verify immutable clean source inputs before declaring a qualified build.

This checks publication with a read-only fetch from the Kent fork and ancestry
of the advertised branch. It does not mutate a working tree or publish code.
"""
import json
from pathlib import Path
import subprocess
import sys
import tomllib

REPOSITORIES = ('keripy', 'dolly', 'kf-registrar', 'kf-observer', 'witness-hk', 'locksmith')
BRANCHES = ('v2-e2e', 'master', *('parity/native-v2',) * 4)


def git(root, *args):
    """Return checked Git output from the explicitly supplied source checkout."""
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def check(paths):
    """Verify six sources and return deterministic revisions and core requirements.

    paths follows REPOSITORIES order. Every consumer must pin the exact core
    HEAD, all tracked/untracked inputs must be clean, and each SHA must be
    reachable from its authorized published Kent branch. Generated logs belong
    outside these checkouts so they cannot become undeclared build inputs.
    """
    if len(paths) != len(REPOSITORIES):
        raise ValueError('Supply all six source checkouts')
    result = {}
    core = git(paths[0], 'rev-parse', 'HEAD')
    for path, repo, branch in zip(paths, REPOSITORIES, BRANCHES, strict=True):
        root = Path(path).resolve()
        if git(root, 'status', '--porcelain'):
            raise ValueError(f'{repo} has uncommitted build inputs')
        revision = git(root, 'rev-parse', 'HEAD')
        url = f'https://github.com/kentbull/{repo}.git'
        subprocess.run(['git', '-C', str(root), 'fetch', '--quiet', url, branch], check=True)
        subprocess.run(['git', '-C', str(root), 'merge-base', '--is-ancestor', revision, 'FETCH_HEAD'], check=True)
        if repo != 'keripy':
            project = tomllib.loads((root / 'pyproject.toml').read_text())['project']
            pins = [item for item in project['dependencies'] if item.lower().startswith('keri @')]
            if len(pins) != 1 or not pins[0].endswith('keripy.git@' + core):
                raise ValueError(f'{repo} does not pin the selected shared core')
        result[repo] = {'revision': revision, 'publishedBranch': branch, 'repository': url}
    return result


if __name__ == '__main__':
    print(json.dumps(check(sys.argv[1:]), indent=2, sort_keys=True))
