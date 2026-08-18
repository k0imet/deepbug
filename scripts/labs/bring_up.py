#!/usr/bin/env python3
"""bring_up.py — bootstrap all DeepBug benchmark labs into ~/.deepbug_labs.

Starts/repairs the local vulnerable-by-design stack so `benchmark_labs.py`
(and `test_auth_session.py`) are reproducibly green after a machine or /tmp
wipe. Health-checks each target; skips what's already up.

Targets:
  3000  Juice Shop   (docker)
  5000  VAmPI        (docker)
  5013  DVGA         (clone + venv, ~/.deepbug_labs/dvga)
  8081  crAPI ident  (docker, requires ./keys bind-mount exists)
  8082  crAPI gw     (docker)
  9876  validator lab({repo}/scripts/labs/lab_server.py)
  9878  mock auth    ({repo}/scripts/labs/../.authlab/mock_auth.py)

Usage:
  python3 scripts/labs/bring_up.py            # up + health check
  python3 scripts/labs/bring_up.py juice      # one target only
"""

import os
import sys
import time
import shutil
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
LABS = pathlib.Path.home() / '.deepbug_labs'

TARGETS = {
    'juice': (3000, ['docker', 'start', 'juiceshop']),
    'vampi': (5000, ['docker', 'start', 'vampi']),
    'dvga': (5013, None),      # special-cased
    'crapi': (8081, None),     # special-cased
    'lab': (9876, None),       # special-cased
    'mock': (9878, None),      # special-cased
}


def up_docker_containers():
    for c in ('juiceshop', 'vampi'):
        subprocess.run(['docker', 'start', c], capture_output=True)


def up_dvga():
    d = LABS / 'dvga'
    if not (d / 'app.py').exists():
        subprocess.run(['git', 'clone', '--depth', '1',
                        'https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application.git', str(d)],
                       check=True)
    venv = d / 'venv'
    if not (venv / 'bin' / 'python').exists():
        subprocess.run(['python3', '-m', 'venv', str(venv)], check=True)
        deps = ['graphene==2.1.9', 'Flask==2.2.2', 'flask-graphql==2.0.1',
                'Flask-GraphQL-Auth==1.3.3', 'mongoengine', 'werkzeug==2.2.2',
                'itsdangerous==2.1.2', 'jinja2==3.1.2', 'click==8.1.3',
                'flask-sqlalchemy==2.5.1', 'sqlalchemy==1.4.46',
                'graphql_ws', 'flask_sockets', 'graphene-sqlalchemy==2.3.0']
        subprocess.run([str(venv / 'bin' / 'pip'), 'install', '-q', *deps], check=True)
    # init DB + seed servermode
    subprocess.run([str(venv / 'bin' / 'python'), '-c',
                    ("from app import app, db\nfrom core import models\n"
                     "with app.app_context():\n db.create_all()\n"
                     " if not models.ServerMode.query.first():\n"
                     "  db.session.add(models.ServerMode(hardened=False)); db.session.commit()")],
                   cwd=str(d), capture_output=True)
    if not _port(5013):
        _spawn([str(venv / 'bin' / 'python'), 'app.py'], cwd=d)


def up_crapi():
    keys = LABS / 'crapi' / 'deploy' / 'docker' / 'keys'
    if not keys.exists():
        print('  crAPI: cloning to ~/.deepbug_labs/crapi (keys bind-mount needed)')
        subprocess.run(['git', 'clone', '--depth', '1',
                        'https://github.com/OWASP/crAPI.git', str(LABS / 'crapi')], check=True)
    subprocess.run(['docker', 'start', 'crapi-identity'], capture_output=True)
    subprocess.run(['docker', 'start', 'crapi-community'], capture_output=True)


def up_lab_server():
    _spawn([sys.executable, str(ROOT / 'scripts' / 'labs' / 'lab_server.py')])


def up_mock_auth():
    _spawn([sys.executable, str(ROOT / '.authlab' / 'mock_auth.py')])


def _port(n):
    import socket
    s = socket.socket()
    try:
        s.bind(('127.0.0.1', n))
        return False  # free -> not running
    except OSError:
        return True
    finally:
        s.close()


def _spawn(argv, cwd=None, log=None):
    log = log or os.devnull
    kwargs = dict(stdout=open(log, 'ab'), stderr=subprocess.STDOUT,
                  start_new_session=True, stdin=subprocess.DEVNULL)
    if cwd is not None:
        kwargs['cwd'] = str(cwd)
    return subprocess.Popen(argv, **kwargs)


def main():
    LABS.mkdir(parents=True, exist_ok=True)
    selected = sys.argv[1:] or list(TARGETS)
    for name in selected:
        if name == 'dvga':
            up_dvga()
        elif name == 'crapi':
            up_crapi()
        elif name == 'lab':
            up_lab_server()
        elif name == 'mock':
            up_mock_auth()
        elif name in TARGETS:
            subprocess.run(TARGETS[name][1], capture_output=True)
    print('waiting for health...')
    time.sleep(6)
    for name in selected:
        port = TARGETS[name][0]
        print(f'  {name:6} :{port} ' +
              ('UP' if _port(port) else 'DOWN'))
    # lab integration
    print('\nlabs ready. run: python3 scripts/benchmark_labs.py')


if __name__ == '__main__':
    main()
