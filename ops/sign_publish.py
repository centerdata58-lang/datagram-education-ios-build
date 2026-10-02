"""Owner-triggered TestFlight signing. Credentials arrive through Actions secrets.
Never installs repository credentials or moves credentials between repositories.
Public logs contain phase names only; private output stays on the ephemeral Mac.
"""
from __future__ import annotations
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

BUNDLE = 'com.datagram.education'
TEAM = 'GL42FYG3RK'
APP_ID = '6818438462'
SECRET_NAMES = ('IOS_CERTIFICATE_BASE64', 'IOS_CERTIFICATE_PASSWORD',
                'IOS_PROVISIONING_PROFILE_BASE64', 'ASC_PRIVATE_KEY',
                'ASC_KEY_ID', 'ASC_ISSUER_ID')

class GateError(RuntimeError):
    pass

def require(condition: bool, code: str) -> None:
    if not condition:
        raise GateError(code)

def current_commit(source: Path) -> str:
    return subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()

def source_version(text: str) -> tuple[str, int]:
    match = re.search(r'^version:\s*(\d+\.\d+\.\d+)\+(\d+)\s*$', text, re.M)
    require(match is not None, 'invalid_source_version')
    return match.group(1), int(match.group(2))

def verify_native_report(report: dict, commit: str) -> None:
    require(bool(re.fullmatch(r'[0-9a-f]{40}', commit)), 'invalid_commit')
    require(report.get('commit') == commit, 'native_evidence_commit_mismatch')
    require(report.get('bundleId') == BUNDLE, 'native_bundle_mismatch')
    require(report.get('nativeTestsPassed') is True, 'native_tests_not_passed')
    require({v.get('family') for v in report.get('devices', [])} == {'iPhone', 'iPad'},
            'both_native_device_families_required')

def verify_profile(profile: dict, identity: str, now: dt.datetime | None = None) -> None:
    now = now or dt.datetime.now(dt.timezone.utc)
    entitlement = profile.get('Entitlements', {})
    require(profile.get('TeamIdentifier') == [TEAM], 'wrong_apple_team')
    require(entitlement.get('application-identifier') == f'{TEAM}.{BUNDLE}', 'wrong_profile_app')
    require(entitlement.get('aps-environment') == 'production', 'production_push_entitlement_required')
    require(entitlement.get('get-task-allow') is False, 'development_profile_rejected')
    require(not profile.get('ProvisionedDevices') and not profile.get('ProvisionsAllDevices'),
            'app_store_profile_required')
    expiry = profile.get('ExpirationDate')
    require(isinstance(expiry, dt.datetime), 'profile_expiry_missing')
    expiry = expiry.replace(tzinfo=dt.timezone.utc) if expiry.tzinfo is None else expiry
    require(expiry > now, 'profile_expired')
    require(any(hashlib.sha1(value).hexdigest().upper() == identity
                for value in profile.get('DeveloperCertificates', [])), 'certificate_not_in_profile')
    require(bool(re.fullmatch(r'[0-9A-Fa-f-]{36}', profile.get('UUID', ''))), 'invalid_profile_uuid')

def next_build(versions: list[str], source_floor: int) -> int:
    require(source_floor > 0, 'invalid_source_build')
    require(all(re.fullmatch(r'\d+', value) for value in versions), 'noninteger_remote_build_needs_review')
    return max(source_floor, max([int(v) for v in versions], default=0) + 1)

def raw_ecdsa(der: bytes) -> bytes:
    """Strict DER SEQUENCE(INTEGER r, INTEGER s) -> JWT ES256 representation."""
    def item(offset: int, tag: int) -> tuple[bytes, int]:
        require(offset + 2 <= len(der) and der[offset] == tag, 'invalid_ecdsa_signature')
        length = der[offset + 1]
        require(length < 128 and offset + 2 + length <= len(der), 'invalid_ecdsa_length')
        return der[offset + 2:offset + 2 + length], offset + 2 + length
    sequence, end = item(0, 0x30)
    require(end == len(der) and len(sequence) > 0, 'invalid_ecdsa_sequence')
    first, offset = item(2, 0x02)
    second, end = item(offset, 0x02)
    require(end == len(der), 'invalid_ecdsa_tail')
    values = []
    for value in (first, second):
        require(bool(value) and not value[0] & 0x80, 'invalid_ecdsa_integer')
        number = int.from_bytes(value, 'big')
        require(0 < number < 2 ** 256, 'invalid_ecdsa_integer')
        values.append(number.to_bytes(32, 'big'))
    return b''.join(values)

def pin_signing(project: str, identity: str, profile_uuid: str) -> str:
    require(bool(re.fullmatch(r'[A-F0-9]{40}', identity)), 'invalid_signing_identity')
    require(bool(re.fullmatch(r'[0-9A-Fa-f-]{36}', profile_uuid)), 'invalid_profile_uuid')
    anchor = f'PRODUCT_BUNDLE_IDENTIFIER = {BUNDLE};'
    require(project.count(anchor) == 3, 'unexpected_runner_configuration')
    addition = '\n'.join([
        anchor, f'\t\t\t\tDEVELOPMENT_TEAM = {TEAM};',
        '\t\t\t\t"CODE_SIGN_STYLE[sdk=iphoneos*]" = Manual;',
        f'\t\t\t\t"CODE_SIGN_IDENTITY[sdk=iphoneos*]" = "{identity}";',
        f'\t\t\t\t"PROVISIONING_PROFILE_SPECIFIER[sdk=iphoneos*]" = "{profile_uuid}";',
    ])
    return project.replace(anchor, addition)

class Apple:
    def __init__(self, key: Path, log: Path):
        self.key, self.log = key, log
        self.key_id, self.issuer = os.environ['ASC_KEY_ID'], os.environ['ASC_ISSUER_ID']
        require(bool(re.fullmatch(r'[A-Z0-9]{10}', self.key_id)), 'invalid_apple_key_id')
        require(bool(re.fullmatch(r'[0-9a-fA-F-]{36}', self.issuer)), 'invalid_apple_issuer')

    def get(self, path: str) -> dict:
        parsed = urllib.parse.urlsplit(path)
        require(not parsed.scheme and not parsed.netloc and path.startswith('/v1/'), 'invalid_apple_path')
        encode = lambda data: base64.urlsafe_b64encode(data).decode().rstrip('=')
        head = encode(json.dumps({'alg':'ES256', 'kid':self.key_id, 'typ':'JWT'}).encode())
        body = encode(json.dumps({'iss':self.issuer, 'iat':int(time.time())-10,
                                  'exp':int(time.time())+300, 'aud':'appstoreconnect-v1'}).encode())
        message = (head + '.' + body).encode()
        signed = subprocess.run(['openssl','dgst','-sha256','-sign',str(self.key)], input=message,
                                capture_output=True, check=True, timeout=15).stdout
        token = head + '.' + body + '.' + encode(raw_ecdsa(signed))
        request = urllib.request.Request('https://api.appstoreconnect.apple.com' + path,
                    headers={'Authorization':'Bearer '+token, 'Accept':'application/json'})
        with urllib.request.urlopen(request, timeout=20) as response:
            return json.load(response)

    def versions(self) -> list[str]:
        data = self.get('/v1/apps/' + APP_ID)
        require(data['data']['attributes']['bundleId'] == BUNDLE, 'apple_app_bundle_mismatch')
        path = '/v1/builds?' + urllib.parse.urlencode({'filter[app]':APP_ID,'limit':'200'})
        versions = []
        for _ in range(20):
            response = self.get(path)
            for value in response.get('data', []):
                version = value.get('attributes', {}).get('version')
                require(isinstance(version, str), 'missing_remote_build_version')
                versions.append(version)
            following = response.get('links', {}).get('next')
            if not following:
                return versions
            parsed = urllib.parse.urlsplit(following)
            require(parsed.scheme == 'https' and parsed.netloc == 'api.appstoreconnect.apple.com',
                    'untrusted_apple_pagination')
            path = parsed.path + ('?' + parsed.query if parsed.query else '')
        raise GateError('build_history_incomplete')

def main(source: Path) -> None:
    require(sys.platform == 'darwin', 'macos_required')
    require(os.environ.get('GITHUB_REPOSITORY') == 'centerdata58-lang/datagram-education-ios-build',
            'wrong_build_repository')
    require(os.environ.get('GITHUB_ACTOR') == 'centerdata58-lang', 'owner_required')
    require(os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch', 'manual_dispatch_required')
    source = source.resolve()
    require(source.is_dir(), 'private_source_missing')
    commit = current_commit(source)
    require(commit == os.environ.get('SOURCE_SHA'), 'source_commit_mismatch')
    verify_native_report(json.loads((source/'artifacts/ios/native-validation.json').read_text()), commit)
    require(all(os.environ.get(name) for name in SECRET_NAMES), 'signing_configuration_required')
    app_version, source_floor = source_version((source/'pubspec.yaml').read_text())
    os.umask(0o077)
    temporary = Path(tempfile.mkdtemp(prefix='education-signing-', dir=os.environ['RUNNER_TEMP']))
    keychain = temporary/'education.keychain-db'
    p8_dir = temporary/'private_keys'
    p8_dir.mkdir()
    installed_profiles: list[Path] = []
    log = temporary/'private-signing.log'
    project = source/'ios/Runner.xcodeproj/project.pbxproj'
    project_before = project.read_bytes()
    created_keychain = False

    def run(args: list[str], timeout: int = 300, cwd: Path | None = None) -> bytes:
        process = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 timeout=timeout, cwd=cwd or source)
        with log.open('ab') as output:
            output.write(process.stdout)
        require(process.returncode == 0, 'signing_command_failed')
        return process.stdout
    try:
        p12, profile_file = temporary/'distribution.p12', temporary/'education.mobileprovision'
        p12.write_bytes(base64.b64decode(os.environ['IOS_CERTIFICATE_BASE64'], validate=True))
        profile_file.write_bytes(base64.b64decode(os.environ['IOS_PROVISIONING_PROFILE_BASE64'], validate=True))
        key_id = os.environ['ASC_KEY_ID']
        require(bool(re.fullmatch(r'[A-Z0-9]{10}', key_id)), 'invalid_apple_key_id')
        p8 = p8_dir/('AuthKey_'+key_id+'.p8')
        p8.write_text(os.environ['ASC_PRIVATE_KEY'])
        apple = Apple(p8, log)
        build = next_build(apple.versions(), source_floor)
        password = secrets.token_hex(24)
        run(['security','create-keychain','-p',password,str(keychain)])
        created_keychain = True
        run(['security','set-keychain-settings','-lut','21600',str(keychain)])
        run(['security','unlock-keychain','-p',password,str(keychain)])
        run(['security','import',str(p12),'-k',str(keychain),'-P',os.environ['IOS_CERTIFICATE_PASSWORD'],
             '-T','/usr/bin/codesign','-T','/usr/bin/security'])
        run(['security','list-keychains','-d','user','-s',str(keychain)])
        run(['security','default-keychain','-d','user','-s',str(keychain)])
        run(['security','set-key-partition-list','-S','apple-tool:,apple:,codesign:','-s','-k',password,str(keychain)])
        available = run(['security','find-identity','-v','-p','codesigning',str(keychain)]).decode()
        identities = re.findall(r'\b([A-F0-9]{40})\b\s+"(?:Apple Distribution|iPhone Distribution)', available)
        require(len(identities) == 1, 'one_distribution_identity_required')
        identity = identities[0]
        profile = plistlib.loads(run(['security','cms','-D','-i',str(profile_file)]))
        verify_profile(profile, identity)
        for relative in ('Library/MobileDevice/Provisioning Profiles',
                         'Library/Developer/Xcode/UserData/Provisioning Profiles'):
            folder = Path.home()/relative
            folder.mkdir(parents=True, exist_ok=True)
            destination = folder/(profile['UUID']+'.mobileprovision')
            if destination.exists():
                require(destination.read_bytes() == profile_file.read_bytes(), 'profile_install_collision')
            else:
                shutil.copy2(profile_file, destination)
                installed_profiles.append(destination)
        export = temporary/'ExportOptions.plist'
        export.write_bytes(plistlib.dumps({'method':'app-store-connect','teamID':TEAM,'signingStyle':'manual',
             'signingCertificate':identity,'provisioningProfiles':{BUNDLE:profile['UUID']},
             'uploadSymbols':True,'stripSwiftSymbols':True,'testFlightInternalTestingOnly':True}))
        project.write_text(pin_signing(project_before.decode(), identity, profile['UUID']))
        print('SIGNING: validated existing Education profile and distribution identity', flush=True)
        run(['flutter','build','ipa','--release','--build-name='+app_version,'--build-number='+str(build),
             '--export-options-plist='+str(export)], timeout=1500)
        run(['python3','ops/ios/verify_signed.py','--app','build/ios/archive/Runner.xcarchive/Products/Applications/Runner.app',
             '--build-number',str(build),'--export-options',str(export)], timeout=120)
        ipas = list((source/'build/ios/ipa').glob('*.ipa'))
        require(len(ipas) == 1, 'one_verified_ipa_required')
        print('IPA: native tests and signed-archive verification passed', flush=True)
        run(['xcrun','altool','--validate-app','--file',str(ipas[0]),'--type','ios',
             '--apiKey',apple.key_id,'--apiIssuer',apple.issuer], timeout=300, cwd=temporary)
        run(['xcrun','altool','--upload-app','--file',str(ipas[0]),'--type','ios',
             '--apiKey',apple.key_id,'--apiIssuer',apple.issuer], timeout=900, cwd=temporary)
        print('UPLOAD: Apple upload command completed; processing and TestFlight visibility still require confirmation', flush=True)
        summary = os.environ.get('GITHUB_STEP_SUMMARY')
        if summary:
            with open(summary, 'a') as output:
                output.write(f'## Education iOS upload\nVersion {app_version} ({build}).\n'
                             'Signed IPA verified and upload command succeeded. '
                             'Not a confirmation of Apple processing or TestFlight availability.\n')
    finally:
        project.write_bytes(project_before)
        for installed in installed_profiles:
            installed.unlink(missing_ok=True)
        if created_keychain:
            subprocess.run(['security','delete-keychain',str(keychain)], capture_output=True, check=False, timeout=30)
        shutil.rmtree(temporary, ignore_errors=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    arguments = parser.parse_args()
    try:
        main(arguments.source)
    except GateError as error:
        print('STOP: '+str(error), file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('STOP: signing or Apple communication failed; no private details published', file=sys.stderr)
        sys.exit(1)
