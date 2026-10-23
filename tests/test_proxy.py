from __future__ import annotations

import importlib.util
import sys
import types
import unittest
from pathlib import Path

# A tiny stand-in for mitmproxy HTTP types so the business logic can be
# tested offline; real traffic still requires mitmdump at runtime.
http = types.ModuleType('mitmproxy.http')
class FakeResponse:
    def __init__(self, status_code: int, content: bytes, headers=None):
        self.status_code = status_code
        self.content = content
        self.headers = dict(headers or {})
    @classmethod
    def make(cls, status_code=200, content=b'', headers=None):
        return cls(status_code, content, headers)
http.Response = FakeResponse
http.HTTPFlow = object
mitmproxy = types.ModuleType('mitmproxy')
mitmproxy.http = http
sys.modules['mitmproxy'] = mitmproxy
sys.modules['mitmproxy.http'] = http
modpath = Path(__file__).resolve().parents[1] / 'assembly_proxy.py'
spec = importlib.util.spec_from_file_location('assembly_proxy', modpath)
addon = importlib.util.module_from_spec(spec)
spec.loader.exec_module(addon)

class FakeRequest:
    def __init__(self, path, method='GET', headers=None):
        self.path = path
        self.method = method
        self.headers = dict(headers or {})
class FakeFlow:
    def __init__(self, path, method='GET', headers=None, response=None):
        self.request = FakeRequest(path, method, headers)
        self.response = response

class AssemblyProxyTests(unittest.TestCase):
    def setUp(self):
        self.proxy = addon.AssemblyOnlyProxy()
        self.asset_path = '/live/abhotupdates/ios/1.126.16/codepatch/assembly-csharp-patch'
        self.manifest_path = '/live/abhotupdates/ios/1.126.16/fileinfo'

    def test_asset_full(self):
        flow = FakeFlow(self.asset_path)
        self.proxy.request(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(flow.response.content, self.proxy.asset)
        self.assertEqual(int(flow.response.headers['Content-Length']), len(self.proxy.asset))

    def test_cdn_asset_hash_suffixes(self):
        # CDN URLs seen in user logs have /gameassetbundles/codepatch/...
        # They may end in version/hash suffixes rather than a bare name.
        variants = [
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch',
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch_0123456789abcdef',
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch.0123456789abcdef.gz',
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch.bytes.gz?version=123',
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch-0123456789ABCDEF',
            # Exact observed game CDN URL: the final '=' of base64 is encoded
            # as ~3D, which the earlier regex did not permit.
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch.U6HNZ6HuhXpDCGzXQhn2VsL5rVs~3D',
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch.u6hnz6huhxpdcgzxqhn2vsl5rvs~3d',
            # Other base64 URL escapes may appear in future digests.
            '/live/ABHotUpdates/ios/1.132.10/gameassetbundles/codepatch/assembly-csharp-patch.ab~2fcd~2bef~3d',
        ]
        for path in variants:
            with self.subTest(path=path):
                self.assertTrue(addon.is_assembly(path))
                flow = FakeFlow(path)
                self.proxy.request(flow)
                self.assertEqual(flow.response.status_code, 200)
                self.assertEqual(flow.response.content, self.proxy.asset)

    def test_does_not_match_similar_basenames(self):
        for path in (
            '/other/codepatch/assembly-csharp-patcher',
            '/other/codepatch/assembly-csharp-patchx',
            '/other/codepatch/different-assembly-csharp-patch',
            '/other/avatar/assetindexer',
            '/other/codepatch/assembly-csharp-patch/another-asset',
            '/other/codepatch/assembly-csharp-patch.not~valid',
            '/other/codepatch/assembly-csharp-patch.abc~3',
        ):
            with self.subTest(path=path):
                self.assertFalse(addon.is_assembly(path))
                flow = FakeFlow(path)
                self.proxy.request(flow)
                self.assertIsNone(flow.response)

    def test_asset_range(self):
        flow = FakeFlow(self.asset_path, headers={'Range': 'bytes=10-20'})
        self.proxy.request(flow)
        self.assertEqual(flow.response.status_code, 206)
        self.assertEqual(flow.response.content, self.proxy.asset[10:21])
        self.assertEqual(flow.response.headers['Content-Range'], f'bytes 10-20/{len(self.proxy.asset)}')

    def test_suffix_range(self):
        flow = FakeFlow(self.asset_path, headers={'Range': 'bytes=-4'})
        self.proxy.request(flow)
        self.assertEqual(flow.response.status_code, 206)
        self.assertEqual(flow.response.content, self.proxy.asset[-4:])

    def test_unsupported_range(self):
        flow = FakeFlow(self.asset_path, headers={'Range': 'bytes=999999-'})
        self.proxy.request(flow)
        self.assertEqual(flow.response.status_code, 416)

    def test_head(self):
        flow = FakeFlow(self.asset_path, method='HEAD')
        self.proxy.request(flow)
        self.assertEqual(flow.response.status_code, 200)
        self.assertEqual(flow.response.content, b'')
        self.assertEqual(flow.response.headers['Content-Length'], str(len(self.proxy.asset)))

    def test_manifest_row_only(self):
        old = b'cache_res,hello\r\ncodepatch/assembly-csharp-patch,oldsha,147904,3,oldsha2,31258,True,0\r\navatar/assetindexer,untouched\r\n'
        flow = FakeFlow(self.manifest_path,
                        headers={'If-None-Match': 'etag','Range':'bytes=0-20'},
                        response=FakeResponse(200,old, {'ETag':'old-etag'}))
        self.proxy.request(flow)
        self.assertNotIn('If-None-Match', flow.request.headers)
        self.assertNotIn('Range', flow.request.headers)
        self.proxy.response(flow)
        self.assertEqual(flow.response.content,
                         b'cache_res,hello\r\n'+self.proxy.line+b'\r\navatar/assetindexer,untouched\r\n')
        self.assertNotIn('ETag', flow.response.headers)

    def test_manifest_missing_line_untouched(self):
        old=b'cache_res,abc\navatar/assetindexer,def\n'
        flow=FakeFlow(self.manifest_path, response=FakeResponse(200, old))
        self.proxy.response(flow)
        self.assertEqual(flow.response.content, old)

    def test_unrelated_traffic_untouched(self):
        flow = FakeFlow('/random/report.garena/log')
        self.proxy.request(flow)
        self.assertIsNone(flow.response)
        flow = FakeFlow('/other/assetindexer.gz')
        self.proxy.request(flow)
        self.assertIsNone(flow.response)
        flow = FakeFlow('/fileinfo', response=FakeResponse(200,b'whatever'))
        self.proxy.response(flow)
        self.assertEqual(flow.response.content,b'whatever')

if __name__ == '__main__':
    unittest.main()
