"""Real local Git tags/checkouts; fake dependencies; no network or admin step."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'scripts/install_frictionless.sh'
PUBLIC = 'https://github.com/rohansiddam/Synthe'
REAL_GIT = shutil.which('git')
HELPER = r'''
import json, os, pathlib, subprocess, sys
kind = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ['TEST_COMMAND_LOG'], 'a') as stream:
    stream.write(json.dumps([kind, *args]) + '\n')
if kind == 'git':
    if 'clone' in args:
        if os.environ.get('TEST_CLONE_FAILS') == 'yes':
            sys.exit(128)
        args = [os.environ['TEST_RELEASE_URL'] if a == os.environ['TEST_PUBLIC_URL'] else a for a in args]
        result = subprocess.run([os.environ['TEST_REAL_GIT'], *args])
        if result.returncode == 0:
            subprocess.run([os.environ['TEST_REAL_GIT'], '-C', args[-1], 'remote', 'set-url',
                            'origin', os.environ['TEST_PUBLIC_URL']], check=True)
        sys.exit(result.returncode)
    sys.exit(subprocess.run([os.environ['TEST_REAL_GIT'], *args]).returncode)
if kind == 'test-python':
    assert args[:2] == ['-m', 'venv']
    target = pathlib.Path(args[-1]) / 'bin' / 'pip'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(pathlib.Path(__file__).read_text())
    target.chmod(0o755)
if kind == 'pip':
    pathlib.Path('build-generated-by-pip').write_text('fixture')
'''


@pytest.fixture
def case(tmp_path):
    home = tmp_path / "home space's $literal"
    home.mkdir()
    commands = tmp_path / 'bin'
    commands.mkdir()
    log = tmp_path / 'commands.jsonl'
    repo = tmp_path / 'release'
    repo.mkdir()
    env = {**os.environ, 'HOME': str(home), 'PATH': f'{commands}:/usr/bin:/bin',
           'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
           'GIT_TERMINAL_PROMPT': '0', 'TEST_COMMAND_LOG': str(log),
           'TEST_REAL_GIT': REAL_GIT, 'TEST_RELEASE_URL': repo.as_uri(),
           'TEST_PUBLIC_URL': PUBLIC, 'TEST_PYTHON': str(commands / 'test-python'),
           'TMPDIR': str(tmp_path)}
    for key in ('SYNTHE_REF', 'SYNTHE_EXPECTED_COMMIT', 'TEST_CLONE_FAILS', 'GIT_DIR',
                'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS'):
        env.pop(key, None)

    def git(*args, cwd=repo):
        return subprocess.run([REAL_GIT, '-c', 'commit.gpgsign=false', '-c', 'tag.gpgsign=false',
                               '-C', str(cwd), *args], env=env, check=True,
                              capture_output=True, text=True).stdout.strip()

    git('init', '-q', '--object-format=sha1', '-b', 'main')
    git('config', 'user.name', 'Installer fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    (repo / 'deploy/macos').mkdir(parents=True)
    (repo / 'deploy/macos/find-python.sh').write_text('echo "$TEST_PYTHON"\n')
    (repo / '.gitignore').write_text('ignored-fixture\n')
    (repo / 'version.txt').write_text('first release\n')
    git('add', '.')
    git('commit', '-qm', 'Release fixture one')
    sha = git('rev-parse', 'HEAD')
    git('tag', '-a', 'v0.7.1', '-m', 'Annotated release fixture')
    (repo / 'version.txt').write_text('second release\n')
    git('commit', '-qam', 'Release fixture two')
    other_sha = git('rev-parse', 'HEAD')
    git('tag', 'v0.7.2')
    for name in ('brew', 'git', 'test-python'):
        path = commands / name
        path.write_text(f'#!{sys.executable}\n' + HELPER)
        path.chmod(0o755)
    source = home / '.synthe-source'

    def run(installer=INSTALLER, **overrides):
        return subprocess.run(['/bin/bash', str(installer)], input='', capture_output=True,
                              text=True, start_new_session=True, timeout=30,
                              env={**env, **overrides})

    def calls():
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def seed(ref='v0.7.1'):
        git('clone', '-q', '--branch', ref, str(repo), str(source), cwd=tmp_path)
        git('remote', 'set-url', 'origin', PUBLIC, cwd=source)

    return SimpleNamespace(home=home, repo=repo, source=source, sha=sha, other_sha=other_sha,
                           git=git, seed=seed, run=run, calls=calls, tmp=tmp_path)


def assert_success(case, result, ref='v0.7.1', sha=None):
    assert result.returncode == 0, result.stdout + result.stderr
    assert f'Installing Synthe {ref} at {sha or case.sha}' in result.stdout
    assert 'bash ~/.synthe/finish-setup.sh' in result.stdout
    assert not (case.home / '.synthe').exists(), 'no admin or secret step may start'
    assert any(row[0] == 'pip' for row in case.calls())
    assert case.git('status', '--porcelain', '--ignored', cwd=case.source) == ''


def assert_no_dependencies(case):
    assert not any(row[0] in {'brew', 'test-python', 'pip'} for row in case.calls())
    assert not (case.home / 'synthe-venv').exists()
    assert not (case.home / '.synthe').exists()


def assert_mismatch_stops_before_dependencies(case, result):
    assert result.returncode == 1
    assert 'Release commit mismatch' in result.stdout
    assert 'Stopped before installing any dependencies' in result.stdout
    assert_no_dependencies(case)


def test_tagged_install_unset_pin_stops_before_the_admin_step(case):
    result = case.run()
    assert_success(case, result)
    clone = next(row for row in case.calls() if 'clone' in row)
    assert clone[clone.index('--branch') + 1] == 'v0.7.1'
    assert any(row[-1:] == ['refs/tags/v0.7.1'] and 'checkout' in row for row in case.calls())


def test_expected_commit_match_installs(case):
    assert_success(case, case.run(SYNTHE_EXPECTED_COMMIT=case.sha))


def test_expected_commit_mismatch_stops_before_dependencies(case):
    result = case.run(SYNTHE_EXPECTED_COMMIT=case.other_sha)
    assert_mismatch_stops_before_dependencies(case, result)
    assert case.git('rev-parse', 'HEAD', cwd=case.source) == case.sha


@pytest.mark.parametrize('pin', ['', 'a' * 39, 'A' * 40, 'main', 'fixture-sensitive-value'])
def test_invalid_expected_commit_is_refused_without_echo(case, pin):
    result = case.run(SYNTHE_EXPECTED_COMMIT=pin)
    assert result.returncode == 1
    assert 'must be a full 40-character lowercase commit SHA' in result.stdout
    assert 'fixture-sensitive-value' not in result.stdout + result.stderr
    assert case.calls() == []


def test_unavailable_tag_does_not_install_main_or_run_python(case):
    result = case.run(TEST_CLONE_FAILS='yes')
    assert result.returncode == 128
    assert len(case.calls()) == 1, 'no retry or fallback is allowed'
    assert '--branch' in case.calls()[0] and 'v0.7.1' in case.calls()[0]
    assert_no_dependencies(case)


def test_clean_checkout_at_requested_tag_is_reused_without_fetch_or_reset(case):
    case.seed()
    before_head = case.git('rev-parse', 'HEAD', cwd=case.source)
    result = case.run(SYNTHE_EXPECTED_COMMIT=case.sha)
    assert_success(case, result)
    assert not any(set(row) & {'clone', 'fetch', 'checkout', 'reset', 'clean'} for row in case.calls())
    assert case.git('rev-parse', 'HEAD', cwd=case.source) == before_head


def test_first_install_keeps_checkout_clean_for_second_run(case):
    assert_success(case, case.run())
    assert_success(case, case.run())
    assert sum('clone' in row for row in case.calls()) == 1


@pytest.mark.parametrize('kind', ['tracked', 'untracked', 'ignored', 'wrong-tag', 'missing-tag',
                                  'wrong-origin', 'not-git', 'symlink', 'dangling-symlink'])
def test_unusable_checkout_is_preserved_with_an_exact_move_command(case, kind):
    if kind in {'symlink', 'dangling-symlink'}:
        case.source.symlink_to(case.repo if kind == 'symlink' else case.tmp / 'missing')
    elif kind == 'not-git':
        case.source.mkdir()
        (case.source / 'keep.txt').write_text('keep')
    else:
        case.seed('v0.7.2' if kind == 'wrong-tag' else 'v0.7.1')
        if kind == 'tracked':
            (case.source / 'version.txt').write_text('keep edit')
        elif kind in {'untracked', 'ignored'}:
            (case.source / ('ignored-fixture' if kind == 'ignored' else 'keep.txt')).write_text('keep')
        elif kind == 'missing-tag':
            case.git('tag', '-d', 'v0.7.1', cwd=case.source)
        elif kind == 'wrong-origin':
            case.git('remote', 'set-url', 'origin', 'https://example.invalid/other', cwd=case.source)
    backup = case.home / '.synthe-source.backup'
    backup.write_text('older backup')
    original_inode = case.source.lstat().st_ino
    result = case.run()
    assert result.returncode == 1
    assert 'Nothing was moved' in result.stdout
    assert_no_dependencies(case)
    assert case.source.lstat().st_ino == original_inode
    command = next(line.strip() for line in result.stdout.splitlines() if line.startswith('  mv -i -- '))
    moved = subprocess.run(['/bin/bash', '-c', command], capture_output=True, text=True, timeout=5)
    assert moved.returncode == 0, moved.stderr
    assert not case.source.exists() and not case.source.is_symlink()
    assert (case.home / '.synthe-source.backup.1').lstat().st_ino == original_inode
    assert backup.read_text() == 'older backup'


def test_reused_checkout_also_checks_expected_commit(case):
    case.seed()
    assert_mismatch_stops_before_dependencies(case, case.run(SYNTHE_EXPECTED_COMMIT=case.other_sha))


def test_git_replacement_cannot_disguise_changed_source_as_the_pinned_commit(case):
    case.seed()
    case.git('replace', case.sha, case.other_sha, cwd=case.source)
    (case.source / 'version.txt').write_text('second release\n')
    case.git('add', 'version.txt', cwd=case.source)
    # Git's ordinary view is now falsely clean at the original HEAD id.
    assert case.git('status', '--porcelain', cwd=case.source) == ''
    result = case.run(SYNTHE_EXPECTED_COMMIT=case.sha)
    assert result.returncode == 1
    assert 'checkout has changed' in result.stdout
    assert_no_dependencies(case)


def test_explicit_release_tag_override(case):
    result = case.run(SYNTHE_REF='v0.7.2', SYNTHE_EXPECTED_COMMIT=case.other_sha)
    assert_success(case, result, 'v0.7.2', case.other_sha)


@pytest.mark.parametrize('ref', ['main', 'HEAD', '--upload-pack=evil', 'v0.7.1; touch sentinel'])
def test_invalid_override_stops_before_dependencies(case, ref):
    result = case.run(SYNTHE_REF=ref)
    assert result.returncode == 1
    assert 'SYNTHE_REF must name a release tag' in result.stdout
    assert case.calls() == []


def test_mutation_removing_release_tag_selection_is_detected(case):
    mutant = case.tmp / 'mutant.sh'
    source = INSTALLER.read_text()
    guard = '--branch "$SYNTHE_RELEASE_TAG" '
    assert source.count(guard) == 1
    mutant.write_text(source.replace(guard, '', 1))
    result = case.run(installer=mutant)
    with pytest.raises(AssertionError):
        assert_success(case, result)
    assert_no_dependencies(case)


def test_mutation_removing_commit_check_is_detected(case):
    mutant = case.tmp / 'mutant.sh'
    source = INSTALLER.read_text()
    guard = 'if [ "${SYNTHE_EXPECTED_COMMIT+x}" = x ] && [ "$INSTALLED_COMMIT" != "$SYNTHE_EXPECTED_COMMIT" ]; then'
    assert source.count(guard) == 1
    mutant.write_text(source.replace(guard, 'if false; then', 1))
    result = case.run(installer=mutant, SYNTHE_EXPECTED_COMMIT=case.other_sha)
    assert result.returncode == 0, result.stdout + result.stderr
    with pytest.raises(AssertionError):
        assert_mismatch_stops_before_dependencies(case, result)


def test_reused_checkout_passes_with_an_insteadof_rewrite(case):
    # Many developers rewrite https://github.com/ to ssh; `remote get-url` reported the rewritten URL and
    # the installer refused its own checkout on a rerun (found 2026-10-23).
    case.seed()
    config = case.tmp / 'gitconfig-rewrite'
    config.write_text('[url "git@github.com:"]\n\tinsteadOf = https://github.com/\n')
    assert_success(case, case.run(GIT_CONFIG_GLOBAL=str(config)))
