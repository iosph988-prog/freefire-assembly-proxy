import unittest,re
from run import ASSET_CDN_RE

class RuntimeScopeTests(unittest.TestCase):
    def test_intercept_only_asset_domains(self):
        accepted=['core-bs.freefiremobile.com','core-gmc.freefiremobile.com:443','core-aw.freefiremobile.com','dl.gmc.freefiremobile.com','dl-bs.freefiremobile.com']
        passed=['loginbp.ppmainecoonghj.com','100067.connect.garena.com','api.potatsocontent.com','2-courier2.push.apple.com','evilcore-bs.freefiremobile.com.example.org']
        for a in accepted:
            self.assertTrue(re.search(ASSET_CDN_RE,a),a)
        for p in passed:
            self.assertFalse(re.search(ASSET_CDN_RE,p),p)
