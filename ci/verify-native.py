#!/usr/bin/env python3
"""Exercise the packaged native service with PostgreSQL and a fake Kubernetes review API."""
import http.server
import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid


def docker(*args, check=True):
    return subprocess.run(['docker', *args], check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.strip()


class ReviewHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.path.endswith('/tokenreviews'):
            response = {'apiVersion': 'authentication.k8s.io/v1', 'kind': 'TokenReview', 'status': {'authenticated': True, 'audiences': ['service-permissions'], 'user': {'username': 'system:serviceaccount:test:proxy', 'groups': ['system:serviceaccounts']}}}
        elif self.path.endswith('/subjectaccessreviews'):
            response = {'apiVersion': 'authorization.k8s.io/v1', 'kind': 'SubjectAccessReview', 'status': {'allowed': True}}
        else:
            self.send_error(404)
            return
        body = json.dumps(response).encode()
        self.send_response(201)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    image = os.environ.get('NATIVE_IMAGE_PREFIX', 'grounds/service-permissions') + ':native-micro-pilot'
    suffix = uuid.uuid4().hex[:12]
    network, database, service = (f'permissions-native-{part}-{suffix}' for part in ('net', 'db', 'app'))
    server = http.server.ThreadingHTTPServer(('0.0.0.0', 0), ReviewHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        docker('network', 'create', network)
        docker('run', '-d', '--name', database, '--network', network, '-e', 'POSTGRES_USER=app', '-e', 'POSTGRES_PASSWORD=app', '-e', 'POSTGRES_DB=app', 'postgres:17-alpine')
        for _ in range(90):
            if subprocess.run(['docker', 'exec', database, 'pg_isready', '-U', 'app'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError('PostgreSQL did not start')
        url = f'jdbc:postgresql://{database}:5432/app?currentSchema=permissions'
        env = {'POSTGRES_URL': url, 'POSTGRES_DIRECT_URL': url, 'POSTGRES_USER': 'app', 'POSTGRES_PASSWORD': 'app', 'KUBERNETES_MASTER': f'http://host.docker.internal:{server.server_port}', 'PERMISSIONS_KEYCLOAK_CLIENT_SECRET': 'test-secret', 'PERMISSIONS_JWT_ISSUER': 'https://example.invalid', 'PERMISSIONS_JWT_PUBLIC_KEY_LOCATION': 'https://example.invalid/key', 'PERMISSIONS_IDENTITY_SYNC_ENABLED': 'false', 'PERMISSIONS_IDENTITY_EVENTS_ENABLED': 'false', 'PERMISSIONS_SNAPSHOT_INVALIDATIONS_ENABLED': 'false'}
        args = ['run', '-d', '--name', service, '--network', network, '--add-host', 'host.docker.internal:host-gateway', '-p', '127.0.0.1::8080']
        for key, value in env.items():
            args.extend(['-e', f'{key}={value}'])
        docker(*args, image)
        port = docker('port', service, '8080/tcp').rsplit(':', 1)[1]
        base = f'http://127.0.0.1:{port}'
        for _ in range(90):
            try:
                urllib.request.urlopen(base + '/q/health/live', timeout=2).close()
                break
            except (OSError, urllib.error.HTTPError):
                time.sleep(1)
        else:
            raise AssertionError('native service did not start')
        docker('exec', database, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'app', '-d', 'app', '-c', "UPDATE permissions.permission_identity_sync_state SET last_success_at=now() WHERE id=1; INSERT INTO permissions.permission_roles (key,name,description,is_default) VALUES ('member','Member','test',true); UPDATE permissions.permission_policy_versions SET version=version+1 WHERE id=1;")
        def request(path, token=True):
            headers = {'Authorization': 'Bearer test-token'} if token else {}
            try:
                with urllib.request.urlopen(urllib.request.Request(base + path, headers=headers), timeout=15) as response:
                    return response.status, json.load(response)
            except urllib.error.HTTPError as error:
                return error.code, json.load(error)
        player = 'b465aebc-e9da-45dd-bf57-d56ab1dfe960'
        for _ in range(15):
            status, body = request(f'/v1/permissions/runtime/players/{player}/snapshot?serverType=proxy')
            if status == 200 and body.get('playerId') == player and 'member' in body.get('roleKeys', []):
                break
            time.sleep(1)
        else:
            raise AssertionError((status, body))
        status, body = request('/v1/permissions/runtime/players/invalid/snapshot?serverType=proxy')
        assert status == 400 and body['status'] == 400 and body['error'] == 'invalid_request', (status, body)
        status, body = request('/v1/permissions/runtime/players/invalid/snapshot', False)
        assert status == 401 and body['status'] == 401, (status, body)
        status, body = request('/q/health/ready', False)
        assert status == 200 and body['status'] == 'UP', (status, body)
        logs = docker('logs', service)
        assert 'policy_version_poll_failed' not in logs, 'snapshot cache refresh failed'
        print('Native Permissions: snapshot, error responses, readiness and cache refresh passed')
    except BaseException:
        print(docker('logs', service, check=False))
        raise
    finally:
        docker('rm', '-f', service, check=False)
        docker('rm', '-f', database, check=False)
        docker('network', 'rm', network, check=False)
        server.shutdown()


if __name__ == '__main__':
    main()
