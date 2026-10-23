import unittest
from pathlib import Path
from build_assembly import BASE, OFFICIAL, OUTPUT, parse_bundle, merge_ifix, repack_bundle, sha1b64

class BuildTests(unittest.TestCase):
    def test_original_bundle(self):
        meta=parse_bundle(OFFICIAL.read_bytes())
        self.assertEqual(len(meta['ifix']),144891)
        self.assertEqual(meta['old_padding'],8)
        self.assertEqual(sha1b64(OFFICIAL.read_bytes()),'MN/boYvloTwVu9f1/wHEnfC0znY=')
    def test_merged_preserves_original_methods(self):
        o=OFFICIAL.read_bytes(); b=BASE.read_bytes()
        merged,official,base,mergedp=merge_ifix(parse_bundle(o)['ifix'],b)
        self.assertEqual((len(official['fixes']),len(base['fixes']),len(mergedp['fixes'])),(71,3,74))
        self.assertEqual(mergedp['methods'][:len(official['methods'])],official['methods'])
        output=repack_bundle(o,merged)
        self.assertEqual(output,(OUTPUT/'assembly-csharp-patch.bytes').read_bytes())
