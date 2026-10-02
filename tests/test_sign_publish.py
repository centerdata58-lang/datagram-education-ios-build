import datetime as dt
import hashlib
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'ops/sign_publish.py'
spec = importlib.util.spec_from_file_location('sign_publish', path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class SigningGates(unittest.TestCase):
    def profile(self):
        return {'TeamIdentifier':[module.TEAM],
            'Entitlements':{'application-identifier':module.TEAM+'.'+module.BUNDLE,
              'aps-environment':'production','get-task-allow':False},
            'ExpirationDate':dt.datetime(2030,1,1),
            'DeveloperCertificates':[b'public-test-certificate'],
            'UUID':'12345678-1234-1234-1234-123456789abc'}
    @property
    def fingerprint(self):
        return hashlib.sha1(b'public-test-certificate').hexdigest().upper()
    def test_profile_matches_original_education_identity(self):
        module.verify_profile(self.profile(), self.fingerprint)
    def test_rejects_other_app_profile(self):
        value=self.profile(); value['Entitlements']['application-identifier']=module.TEAM+'.com.datagram.flex'
        with self.assertRaises(module.GateError): module.verify_profile(value,self.fingerprint)
    def test_rejects_other_team(self):
        value=self.profile(); value['TeamIdentifier']=['OTHER']
        with self.assertRaises(module.GateError): module.verify_profile(value,self.fingerprint)
    def test_rejects_profile_with_device_list(self):
        value=self.profile(); value['ProvisionedDevices']=['example']
        with self.assertRaises(module.GateError): module.verify_profile(value,self.fingerprint)
    def test_rejects_enterprise_profile(self):
        value=self.profile(); value['ProvisionsAllDevices']=True
        with self.assertRaises(module.GateError): module.verify_profile(value,self.fingerprint)
    def test_rejects_development_profile(self):
        value=self.profile(); value['Entitlements']['get-task-allow']=True
        with self.assertRaises(module.GateError): module.verify_profile(value,self.fingerprint)
    def test_rejects_sandbox_push_profile(self):
        value=self.profile(); value['Entitlements']['aps-environment']='development'
        with self.assertRaises(module.GateError): module.verify_profile(value,self.fingerprint)
    def test_rejects_expired_profile(self):
        value=self.profile(); value['ExpirationDate']=dt.datetime(2020,1,1)
        with self.assertRaises(module.GateError): module.verify_profile(value,self.fingerprint)
    def test_rejects_missing_certificate(self):
        with self.assertRaises(module.GateError): module.verify_profile(self.profile(),'0'*40)
    def test_selects_nonreused_build_number(self):
        self.assertEqual(module.next_build(['4','9','8'],5),10)
        self.assertEqual(module.next_build([],5),5)
        self.assertEqual(module.next_build(['1'],8),8)
    def test_noninteger_apple_build_needs_review(self):
        with self.assertRaises(module.GateError): module.next_build(['1.0.1'],5)
    def test_native_report_requires_same_commit_and_both_families(self):
        sha='a'*40; report={'commit':sha,'bundleId':module.BUNDLE,'nativeTestsPassed':True,
                           'devices':[{'family':'iPhone'},{'family':'iPad'}]}
        module.verify_native_report(report,sha)
        with self.assertRaises(module.GateError): module.verify_native_report(report,'b'*40)
        report['devices']=[{'family':'iPhone'}]
        with self.assertRaises(module.GateError): module.verify_native_report(report,sha)
    def test_native_report_cannot_treat_failed_tests_as_pass(self):
        with self.assertRaises(module.GateError): module.verify_native_report(
            {'commit':'a'*40,'bundleId':module.BUNDLE,'nativeTestsPassed':False,
             'devices':[{'family':'iPhone'},{'family':'iPad'}]},'a'*40)
    def test_preserves_semver_and_uses_source_build_floor(self):
        self.assertEqual(module.source_version('name: education\nversion: 1.0.0+5\n'),('1.0.0',5))
        with self.assertRaises(module.GateError): module.source_version('version: missing')
    def test_es256_der_conversion(self):
        first=b'\x00\x80'+b'\x01'*31; second=b'\x02'*32
        data=b'\x02'+bytes([len(first)])+first+b'\x02'+bytes([len(second)])+second
        der=b'\x30'+bytes([len(data)])+data
        self.assertEqual(module.raw_ecdsa(der),first[1:]+second)
    def test_es256_rejects_negative_and_trailing_data(self):
        for value in (b'bad',b'\x30\x06\x02\x01\x80\x02\x01\x01',
                      b'\x30\x06\x02\x01\x01\x02\x01\x01extra'):
            with self.assertRaises(module.GateError): module.raw_ecdsa(value)
    def test_signing_changes_only_education_runner_identifiers(self):
        anchor='PRODUCT_BUNDLE_IDENTIFIER = '+module.BUNDLE+';'
        value='\n'.join([anchor]*3+['PRODUCT_BUNDLE_IDENTIFIER = com.datagram.education.RunnerTests;'])
        result=module.pin_signing(value,self.fingerprint,self.profile()['UUID'])
        self.assertEqual(result.count('CODE_SIGN_STYLE[sdk=iphoneos*]'),3)
        self.assertIn('PRODUCT_BUNDLE_IDENTIFIER = com.datagram.education.RunnerTests;',result)
        with self.assertRaises(module.GateError): module.pin_signing(anchor,self.fingerprint,self.profile()['UUID'])

if __name__=='__main__':unittest.main()
