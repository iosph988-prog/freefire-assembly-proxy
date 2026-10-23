"""Offline integrity and preservation checks for current (1.132.10) payload."""
from pathlib import Path
import gzip
import json
import hashlib
import base64

from build_assembly import OFFICIAL, BASE, OUTPUT, parse_bundle, merge_ifix, sha1b64, serialize
from ifix_codec import parse_ifix

original = OFFICIAL.read_bytes()
base = BASE.read_bytes()
bundle = (OUTPUT/'assembly-csharp-patch.bytes').read_bytes()
compressed = (OUTPUT/'assembly-csharp-patch.gz').read_bytes()
row = (OUTPUT/'fileinfo-line.txt').read_text(encoding='ascii').strip()
report = json.loads((OUTPUT/'build-report.json').read_text(encoding='utf-8'))
assert gzip.decompress(compressed) == bundle, 'GZIP decompression differs from UnityFS'
fields=row.split(',')
assert len(fields)==8 and fields[0]=='codepatch/assembly-csharp-patch' and fields[3]=='3'
assert fields[1]==sha1b64(bundle) and int(fields[2])==len(bundle)
assert fields[4]==sha1b64(compressed) and int(fields[5])==len(compressed)
assert fields[6:] == ['True','0']
orig=parse_bundle(original)
merged=parse_bundle(bundle)
assert orig['second']==merged['second']
assert orig['header'][:30]==merged['header'][:30] and orig['header'][46:64]==merged['header'][46:64]
newparse=parse_ifix(merged['ifix'])
origparse=parse_ifix(orig['ifix'])
baseparse=parse_ifix(base)
assert newparse['methods'][:len(origparse['methods'])] == origparse['methods']
assert newparse['strings'][:len(origparse['strings'])] == origparse['strings']
assert newparse['fixes'][:len(origparse['fixes'])] == origparse['fixes']
assert len(origparse['fixes']) == 71 and len(baseparse['fixes']) == 3 and len(newparse['fixes']) == 74
assert len(newparse['methods']) == len(origparse['methods']) + len(baseparse['methods'])
assert report['merged_asset_sha256'] == hashlib.sha256(bundle).hexdigest()
assert report['fileinfo_row'] == row
assert 'Android/data' in str(baseparse['strings'])
print('VERIFY OK: original 71 fixes preserved + 3 user fixes = 74; UnityFS metadata, GZIP and hashes match.')
print('Original',len(original),'bytes | Merged',len(bundle),'bytes | GZIP',len(compressed),'bytes')
print('IMPORTANT: no runtime/loader or iOS Documents compatibility validation possible offline.')
print(row)
