#!/usr/bin/env python3
"""Exercise Core's Keycloak JWT/admin synchronization and identity event paths."""
import base64
import http.server
import json
import os
import pathlib
import re
import socket
import tempfile
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = pathlib.Path(os.environ.get('NATIVE_CONTRACT_EVIDENCE', 'build/native-core-evidence'))
ROOT.mkdir(parents=True, exist_ok=True)


def docker(*args, check=True):
    return subprocess.run(['docker', *args], check=check, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True).stdout.strip()


def nats_request(port, subject, body):
    with socket.create_connection(('127.0.0.1', int(port)), timeout=5) as connection:
        reader = connection.makefile('rb')
        assert reader.readline().startswith(b'INFO ')
        body = json.dumps(body).encode()
        connection.sendall(b'CONNECT {"verbose":false}\r\nSUB _INBOX.fixture 1\r\nPUB ' + subject.encode() + b' _INBOX.fixture ' + str(len(body)).encode() + b'\r\n' + body + b'\r\n')
        while True:
            line = reader.readline()
            if line == b'PING\r\n':
                connection.sendall(b'PONG\r\n')
            elif line.startswith(b'MSG '):
                response = json.loads(reader.read(int(line.split()[-1])))
                assert 'error' not in response, response
                return response

class WorkloadIssuer:
    def __init__(self):
        self.directory = tempfile.TemporaryDirectory()
        self.key = pathlib.Path(self.directory.name) / 'fixture.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(self.key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        modulus = subprocess.check_output(['openssl', 'rsa', '-in', str(self.key), '-noout', '-modulus'], text=True).strip().split('=', 1)[1]
        self.keys = {'keys': [{'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': 'native-player-fixture', 'e': 'AQAB', 'n': self.encode(bytes.fromhex(modulus))}]}
        keys = self.keys
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                body = json.dumps(keys).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        self.server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    @staticmethod
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b'=').decode()

    def token(self, proxy, audience='grounds-services'):
        now = int(time.time())
        header = self.encode(json.dumps({'alg': 'RS256', 'kid': 'native-player-fixture'}).encode())
        claims = self.encode(json.dumps({'iss': 'https://native-player-fixture.invalid', 'sub': 'system:serviceaccount:test:' + proxy, 'aud': audience, 'iat': now, 'exp': now + 600}).encode())
        unsigned = (header + '.' + claims).encode()
        signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.key)], input=unsigned, stdout=subprocess.PIPE, check=True).stdout
        return unsigned.decode() + '.' + self.encode(signature)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.directory.cleanup()

class NatsClient:
    def __init__(self, port):
        self.socket = socket.create_connection(('127.0.0.1', int(port)), timeout=5)
        self.socket.settimeout(None)
        self.reader = self.socket.makefile('rb')
        assert self.reader.readline().startswith(b'INFO ')
        self.socket.sendall(b'CONNECT {"verbose":false,"headers":false}\r\nPING\r\n')
        assert self.reader.readline() == b'PONG\r\n'

    def send(self, data):
        self.socket.sendall(data)

    def receive(self):
        while True:
            line = self.reader.readline()
            if not line:
                return None
            if line == b'PING\r\n':
                self.send(b'PONG\r\n')
            elif line.startswith(b'MSG '):
                fields = line.split()
                payload = self.reader.read(int(fields[-1]))
                assert self.reader.read(2) == b'\r\n'
                return fields[1].decode(), payload.decode()

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()

def subscribe(port):
    client = NatsClient(port)
    client.send(b'SUB > 1\r\nPING\r\n')
    assert client.reader.readline() == b'PONG\r\n'
    received = []
    def collect():
        try:
            while True:
                item = client.receive()
                if item is None:
                    break
                received.append(item)
        except (OSError, ValueError):
            pass
    threading.Thread(target=collect, daemon=True).start()
    return client, received

def wait(description, check):
    for _ in range(60):
        if check():
            return
        time.sleep(1)
    raise AssertionError('Timeout: ' + description)


def main():
    suffix = uuid.uuid4().hex[:10]
    network, db, nats, app = [f'permissions-core-{part}-{suffix}' for part in ['net', 'db', 'nats', 'app']]
    issuer = WorkloadIssuer()
    player, user = str(uuid.uuid4()), str(uuid.uuid4())
    state = {'name': 'CoreNative', 'users': 0, 'userReads': 0, 'groups': 0, 'tokens': 0}
    observer = None

    class Keycloak(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def respond(self, body, status=200):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', '0')))
            if self.path == '/realms/grounds/protocol/openid-connect/token':
                values = urllib.parse.parse_qs(raw.decode())
                assert values.get('client_secret') == ['fixture-secret']
                state['tokens'] += 1
                self.respond({'access_token': 'fixture-admin-token', 'expires_in': 300})
            else:
                self.respond({}, 404)

        def do_GET(self):
            if self.headers.get('Authorization') != 'Bearer fixture-admin-token':
                self.respond({}, 401)
                return
            path = urllib.parse.urlsplit(self.path)
            representation = {'id': user, 'attributes': {'minecraft_java_uuid': [player], 'minecraft_java_username': [state['name']]}}
            if path.path == '/admin/realms/grounds/users':
                state['users'] += 1
                self.respond([representation] if urllib.parse.parse_qs(path.query).get('first', ['0']) == ['0'] else [])
            elif path.path == f'/admin/realms/grounds/users/{user}':
                state['userReads'] += 1
                self.respond(representation)
            elif path.path == f'/admin/realms/grounds/users/{user}/groups':
                state['groups'] += 1
                self.respond([{'id': 'member-group', 'path': '/members'}])
            else:
                self.respond({}, 404)

    server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), Keycloak)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        docker('network', 'create', network)
        docker('run', '-d', '--name', db, '--network', network, '-e', 'POSTGRES_USER=app', '-e', 'POSTGRES_PASSWORD=app', '-e', 'POSTGRES_DB=app', 'postgres:17-alpine')
        docker('run', '-d', '--name', nats, '--network', network, '-p', '127.0.0.1::4222', 'nats:2-alpine', '-js')
        wait('database TCP', lambda: subprocess.run(['docker', 'exec', db, 'pg_isready', '-h', '127.0.0.1', '-U', 'app'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0)
        port = docker('port', nats, '4222/tcp').rsplit(':', 1)[1]
        nats_request(port, '$JS.API.STREAM.CREATE.MINECRAFT_IDENTITY', {'name': 'MINECRAFT_IDENTITY', 'subjects': ['minecraft-identity.changed']})
        observer, received = subscribe(port)
        env = {'POSTGRES_URL': f'jdbc:postgresql://{db}:5432/app?currentSchema=permissions', 'POSTGRES_DIRECT_URL': f'jdbc:postgresql://{db}:5432/app?currentSchema=permissions', 'POSTGRES_USER': 'app', 'POSTGRES_PASSWORD': 'app', 'PERMISSIONS_INSTANCE_ENVIRONMENT': 'prod', 'PERMISSIONS_KEYCLOAK_CLIENT_SECRET': 'fixture-secret', 'PERMISSIONS_KEYCLOAK_URL': f'http://host.docker.internal:{server.server_port}', 'PERMISSIONS_JWT_ISSUER': 'https://native-player-fixture.invalid', 'PERMISSIONS_JWT_PUBLIC_KEY_LOCATION': f'http://host.docker.internal:{issuer.server.server_port}/jwks', 'PERMISSIONS_IDENTITY_SYNC_ENABLED': 'true', 'PERMISSIONS_IDENTITY_EVENTS_ENABLED': 'true', 'PERMISSIONS_IDENTITY_EVENTS_NATS_URL': f'nats://{nats}:4222', 'PERMISSIONS_IDENTITY_EVENTS_CONSUMER': 'core-fixture', 'PERMISSIONS_SNAPSHOT_INVALIDATIONS_ENABLED': 'true', 'PERMISSIONS_SNAPSHOT_CACHE_NATS_INVALIDATIONS_ENABLED': 'true'}
        args = ['run', '-d', '--name', app, '--network', network, '--add-host', 'host.docker.internal:host-gateway', '-p', '127.0.0.1::8080']
        for k, v in env.items():
            args.extend(['-e', k + '=' + v])
        image = os.environ.get('PERMISSIONS_CORE_IMAGE', os.environ.get('NATIVE_IMAGE_PREFIX', 'grounds/service-permissions') + ':native-micro-pilot')
        docker(*args, image)
        def sql(statement):
            return docker('exec', db, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'app', '-d', 'app', '-Atc', statement)
        wait('Native startup', lambda: 'started in' in docker('logs', app, check=False))
        wait('initial populated Keycloak sync', lambda: sql(f"SELECT minecraft_username FROM permissions.permission_player_identities WHERE player_id='{player}'") == 'CoreNative')
        assert state['tokens'] and state['users'] and state['groups'], state
        wait('initial invalidation delivered', lambda: any(subject == 'permissions.snapshot.invalidated' for subject, body in received))
        state['name'] = 'CoreRenamed'
        nats_request(port, 'minecraft-identity.changed', {'realmId': 'grounds', 'keycloakUserId': user, 'reason': 'minecraft-identity-linked'})
        wait('identity event applied', lambda: sql(f"SELECT minecraft_username FROM permissions.permission_player_identities WHERE player_id='{player}'") == 'CoreRenamed')
        assert state['userReads'] > 0
        wait('event invalidation delivered', lambda: len([s for s, b in received if s == 'permissions.snapshot.invalidated']) >= 2)
        app_port = docker('port', app, '8080/tcp').rsplit(':', 1)[1]
        def token(groups):
            now = int(time.time())
            unsigned = '.'.join(issuer.encode(json.dumps(part).encode()) for part in [{'alg': 'RS256', 'kid': 'native-player-fixture'}, {'iss': 'https://native-player-fixture.invalid', 'sub': user, 'iat': now, 'exp': now + 300, 'groups': groups}]).encode()
            signature = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(issuer.key)], input=unsigned, check=True, stdout=subprocess.PIPE).stdout
            return unsigned.decode() + '.' + issuer.encode(signature)
        def request(path, bearer=None, body=None):
            headers = {'Content-Type': 'application/json'}
            if bearer:
                headers['Authorization'] = 'Bearer ' + bearer
            req = urllib.request.Request(f'http://127.0.0.1:{app_port}' + path, data=json.dumps(body).encode() if body else None, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=10) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, error.read().decode()
        assert request('/v1/permissions/roles')[0] == 401
        admin = token(['GAME_AREA_ACCESS', 'MINECRAFT_PERMISSIONS_PRODUCTION_MANAGE'])
        status, body = request('/v1/permissions/roles', admin, {'name': 'Core Native Members', 'description': 'Native fixture', 'default': True})
        assert status == 201 and body['name'] == 'Core Native Members', (status, body)
        status, body = request('/v1/permissions/roles', admin)
        assert status == 200 and any(r['name'] == 'Core Native Members' for r in body), (status, body)
        status, body = request('/v1/permissions/roles', token(['GAME_AREA_ACCESS', 'MINECRAFT_PERMISSIONS_STAGE_MANAGE']))
        assert status == 403, (status, body)
        invalidations = [json.loads(b) for s, b in received if s == 'permissions.snapshot.invalidated']
        assert all(item['schemaVersion'] == 1 and item['playerId'] == player for item in invalidations)
        logs = docker('logs', app, check=False)
        assert not re.search(r'\b(ERROR|FATAL)\b|Exception|event rejected|sync failed', logs), logs[-7000:]
        (ROOT / 'permissions-core-native.log').write_text(logs)
        (ROOT / 'permissions-core-verification.json').write_text(json.dumps({'image': image, 'keycloakReads': state, 'invalidations': len(invalidations), 'checks': ['initial Keycloak projection with groups', 'identity JetStream refresh and invalidation', 'Core prod JWT admin role CRUD', 'unauthenticated401 and stage-role403']}, indent=2) + '\n')
        print('PASS: Core Permissions Keycloak JWT/admin sync, identity events, invalidation and production authorization')
    except BaseException:
        logs = docker('logs', app, check=False)
        (ROOT / 'permissions-core-failure.log').write_text(logs)
        print(logs[-9000:])
        raise
    finally:
        if observer:
            observer.close()
        server.shutdown()
        issuer.close()
        for container in [app, nats, db]:
            docker('rm', '-f', container, check=False)
        docker('network', 'rm', network, check=False)


if __name__ == '__main__':
    main()
