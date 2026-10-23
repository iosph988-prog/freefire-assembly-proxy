"""Repack official 1.132.10 iOS UnityFS preserving all existing IFix fixes.

Appends the user's provided *unchanged* IFix method bodies as separate
entries. This does not patch the iOS application's file access, bypass
anti-cheat, or guarantee the game will run it; verification is structural.
"""
from __future__ import annotations
import base64
from collections import Counter
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import struct

from lz4.block import compress, decompress
from ifix_codec import parse_ifix

HERE = Path(__file__).resolve().parent
BASE = HERE / 'source' / 'Assembly-CSharp-patch-BASE.bytes'
OFFICIAL = HERE / 'source' / 'assembly-csharp-patch-ORIGINAL-147904.bytes'
OUTPUT = HERE / 'payload'
MAGIC = bytes.fromhex('cba2b40db219a366')
OFFICIAL_SHA1 = 'MN/boYvloTwVu9f1/wHEnfC0znY='
IFIX_HEAD = bytes.fromhex('cba2b40db219a366')
ASSET = 'codepatch/assembly-csharp-patch'


def u32(v: int) -> bytes: return struct.pack('<I',v)
def i32(v: int) -> bytes: return struct.pack('<i',v)
def aup(v: int, b: int) -> int: return (v+b-1)//b*b
def sha1b64(data: bytes) -> str: return base64.b64encode(hashlib.sha1(data).digest()).decode('ascii')
def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()

def str7(s: str) -> bytes:
    data = s.encode('utf-8')
    n = len(data)
    ans = bytearray()
    while n >= 128:
        ans.append((n & 0x7f) | 0x80)
        n >>= 7
    ans.append(n)
    return bytes(ans)+data


def write_method(m):
    b = bytes([m['generic']])+i32(m['type'])+str7(m['method'])
    if m['generic']:
        b += u32(len(m['argids']))+b''.join(i32(x) for x in m['argids'])
        b += u32(len(m['paramIds']))
        for generic, val in m['paramIds']:
            b += bytes([generic]) + (str7(val) if generic else i32(val))
    else:
        b += u32(len(m['paramIds']))+b''.join(i32(x) for x in m['paramIds'])
    return b


def serialize(p):
    b = struct.pack('<Q', 0x66a319b20db4a2cb) + str7(p['bridge'])
    b += u32(len(p['types'])) + b''.join(str7(s) for s in p['types'])
    b += u32(len(p['methods']))
    for m in p['methods']:
        b += u32(len(m['code']))
        b += b''.join(struct.pack('<ii', op, operand) for op,operand in m['code'])
        b += u32(len(m['handlers']))
        b += b''.join(struct.pack('<iiiiii', *h) for h in m['handlers'])
    b += u32(len(p['externMethods']))+b''.join(write_method(m) for m in p['externMethods'])
    b += u32(len(p['strings']))+b''.join(str7(s) for s in p['strings'])
    b += u32(len(p['fields']))
    for f in p['fields']:
        b += bytes([f['is_new']])+i32(f['type'])+str7(f['name'])
        if f['is_new']:
            b += i32(f['extra'][0])+i32(f['extra'][1])
    b += u32(len(p['statics'])) + b''.join(i32(t)+i32(c) for t,c in p['statics'])
    b += p['anon_raw']
    b += str7(p['wrapper']) + str7(p['assembly']) + bytes([p['extra']])
    b += u32(len(p['fixes'])) + b''.join(write_method(x['method'])+i32(x['id']) for x in p['fixes'])
    b += u32(len(p['newclasses'])) + b''.join(str7(s) for s in p['newclasses'])
    return b


def remap_method(m, add_types):
    x = deepcopy(m)
    x['type'] += add_types
    x['argids'] = [v+add_types for v in x['argids']]
    if x['generic']:
        x['paramIds']=[(k,v if k else v+add_types) for k,v in x['paramIds']]
    else:
        x['paramIds'] = [v+add_types for v in x['paramIds']]
    return x


def signature(entry):
    m = entry['method']
    return m['qualified'],m['method'],str(m['params'])


def merge_ifix(official: bytes, base: bytes):
    official_p = parse_ifix(official)
    base_p = parse_ifix(base)
    assert serialize(official_p) == official, 'Official IFix cannot round-trip byte-perfectly'
    assert serialize(base_p) == base, 'Base IFix cannot round-trip byte-perfectly'
    assert (official_p['bridge'],official_p['wrapper'],official_p['assembly']) == (base_p['bridge'],base_p['wrapper'],base_p['assembly']), 'IFix target mismatch'
    assert not (set(map(signature, official_p['fixes'])) & set(map(signature, base_p['fixes']))), 'Overlapping fixed signatures'
    assert base_p['anon_count'] == 0 and not base_p['statics'], 'Unsupported extra static/anonymous setup'

    offsets = dict(methods=len(official_p['methods']),types=len(official_p['types']),ext=len(official_p['externMethods']),strings=len(official_p['strings']),fields=len(official_p['fields']))
    indices = {16:('strings', False), 38:('fields',False), 144:('fields',False),154:('fields',False),
               124:('types',False),142:('types',False),150:('types',False),
               105:('ext',True),175:('ext',True),151:('methods',True)}
    extra_counts = {'strings':len(base_p['strings']),'fields':len(base_p['fields']),
                    'types':len(base_p['types']),'ext':len(base_p['externMethods']),'methods':len(base_p['methods'])}
    used_opcodes = set(op for method in base_p['methods'] for op,_ in method['code'])
    assert all(0 <= op < 2048 for op in used_opcodes), 'Unexpected IFix bytecode opcodes'
    merged = deepcopy(official_p)
    merged['types'].extend(base_p['types'])
    for method in base_p['methods']:
        out=deepcopy(method);new_code=[]
        for opcode, val in method['code']:
            if opcode in indices:
                category, packed = indices[opcode]
                shift = offsets[category]
                if packed:
                    low=val&0xffff
                    assert low < extra_counts[category]
                    assert low + shift < 65536
                    val=(val & 0xffff0000)|(low+shift)
                    if val>=2**31: val-=2**32
                else:
                    assert 0 <= val < extra_counts[category]
                    val += shift
            new_code.append((opcode,val))
        out['code']=new_code
        out['handlers'] = [(k,t+offsets['types'] if t>=0 else t,s,e,hs,he) for k,t,s,e,hs,he in out['handlers']]
        merged['methods'].append(out)
    merged['externMethods'].extend(remap_method(x,offsets['types']) for x in base_p['externMethods'])
    merged['strings'].extend(base_p['strings'])
    for field in base_p['fields']:
        f=deepcopy(field);f['type']+=offsets['types']
        if f['extra']:
            a,b=f['extra'];f['extra']=(a+offsets['types'],b+offsets['methods'] if b>=0 else b)
        merged['fields'].append(f)
    for fix in base_p['fixes']:
        x=deepcopy(fix);x['method']=remap_method(fix['method'],offsets['types']);x['id']+=offsets['methods']
        merged['fixes'].append(x)
    merged['newclasses'].extend(base_p['newclasses'])
    combined = serialize(merged)
    reparsed=parse_ifix(combined)
    assert serialize(reparsed)==combined
    assert reparsed['methods'][:offsets['methods']]==official_p['methods']
    assert len(reparsed['fixes'])==len(official_p['fixes'])+len(base_p['fixes'])
    assert reparsed['fixes'][-len(base_p['fixes']):] == merged['fixes'][-len(base_p['fixes']):]
    return combined,official_p,base_p,reparsed


def parse_bundle(data: bytes):
    assert data.startswith(b'UnityFS\0'), 'Invalid UnityFS header'
    assert struct.unpack_from('>Q',data,30)[0]==len(data),'UnityFS length mismatch'
    info_size=struct.unpack_from('>I',data,38)[0]
    info_uncompressed=struct.unpack_from('>I',data,42)[0]
    assert info_uncompressed==91 and struct.unpack_from('>I',data,46)[0]==0x243, 'Unknown UnityFS layout'
    info=decompress(data[64:64+info_size], uncompressed_size=info_uncompressed)
    assert struct.unpack_from('>I',info,16)[0]==1 and struct.unpack_from('>H',info,28)[0]==0x40
    off=aup(64+info_size,16)
    block=data[off:]
    assert struct.unpack_from('>II',info,20)==(len(block),len(block))
    assert struct.unpack_from('>Q',info,42)[0]==struct.unpack_from('>Q',block,24)[0]
    serialized_size=struct.unpack_from('>Q',block,24)[0]
    assert serialized_size<=len(block)
    assert block[serialized_size:] == b'\0'*(len(block)-serialized_size)
    asset_start=2608
    len_text=struct.unpack_from('<I',block,2636)[0]
    assert block[2640:2648]==IFIX_HEAD
    assert len_text>0
    assert len_text<serialized_size
    first_size=struct.unpack_from('<I',block,2548)[0]
    second_offset=struct.unpack_from('<Q',block,2564)[0]
    assert first_size==aup(32+len_text,4)
    assert second_offset==aup(first_size,8)
    end_first=asset_start+second_offset
    assert len(block[asset_start+32:asset_start+32+len_text])==len_text
    second=block[end_first:serialized_size]
    assert len(second)==216 and second[:4]==u32(31)
    old_ifix=block[2640:2640+len_text]
    ifix_obj=parse_ifix(old_ifix)
    assert ifix_obj['length']==len_text, 'IFix declared size mismatch'
    return {'info':info,'block':block,'header':data[:64], 'offset':off,
            'prefix':block[:2640], 'ifix':old_ifix, 'second':second,
            'old_padding':len(block)-serialized_size}


def repack_bundle(original: bytes, new_ifix: bytes) -> bytes:
    meta=parse_bundle(original)
    first_size=aup(32+len(new_ifix),4)
    second_offset=aup(first_size,8)
    prefix=bytearray(meta['prefix'])
    prefix[2548:2552]=u32(first_size)
    prefix[2564:2572]=struct.pack('<Q',second_offset)
    prefix[2636:2640]=u32(len(new_ifix))
    serialized=bytearray(prefix)+new_ifix+b'\0'*(second_offset-32-len(new_ifix))+meta['second']
    serialized[24:32]=struct.pack('>Q',len(serialized))
    block=bytes(serialized)+b'\0'*(aup(len(serialized),16)-len(serialized))
    info=bytearray(meta['info'])
    info[20:28]=struct.pack('>II',len(block),len(block))
    info[42:50]=struct.pack('>Q',len(serialized))
    compressed=compress(bytes(info),store_size=False)
    data_off=aup(64+len(compressed),16)
    header=bytearray(meta['header'])
    header[38:42]=struct.pack('>I',len(compressed))
    result=header+compressed+b'\0'*(data_off-64-len(compressed))+block
    result[30:38]=struct.pack('>Q',len(result))
    result=bytes(result)
    again=parse_bundle(result)
    assert again['ifix']==new_ifix
    assert again['second']==meta['second']
    assert result[:30]==original[:30]
    assert result[46:64]==original[46:64]
    assert result[data_off:data_off+24]==meta['block'][:24]
    return result


def main():
    base=BASE.read_bytes();original=OFFICIAL.read_bytes()
    assert sha1b64(original)==OFFICIAL_SHA1, 'Original asset SHA1 must match 1.132.10 fileinfo'
    assert base.startswith(MAGIC)
    info=parse_bundle(original)
    combined, orig_p,base_p, merged_p=merge_ifix(info['ifix'], base)
    result=repack_bundle(original, combined)
    packed=gzip.compress(result, compresslevel=9,mtime=0)
    assert gzip.decompress(packed)==result
    row=f'{ASSET},{sha1b64(result)},{len(result)},3,{sha1b64(packed)},{len(packed)},True,0'
    OUTPUT.mkdir(parents=True, exist_ok=True)
    (OUTPUT/'assembly-csharp-patch.bytes').write_bytes(result)
    (OUTPUT/'assembly-csharp-patch.gz').write_bytes(packed)
    (OUTPUT/'fileinfo-line.txt').write_text(row+'\n', encoding='ascii')
    report={'original_uncompressed_bytes':len(original),'original_sha1b64':sha1b64(original),
            'base_ifix_bytes':len(base),'base_sha256':sha256(base),
            'original_ifix_fixes':len(orig_p['fixes']),'base_ifix_fixes':len(base_p['fixes']),
            'merged_ifix_fixes':len(merged_p['fixes']),
            'original_ifix_methods':len(orig_p['methods']),'merged_ifix_methods':len(merged_p['methods']),
            'merged_asset_bytes':len(result),'merged_asset_sha256':sha256(result),
            'gzip_bytes':len(packed),'gzip_sha1b64':sha1b64(packed),
            'fileinfo_row':row,
            'caveat':'Structural tests only. No iOS runtime test, iOS localConfig path compatibility, asset trust or upstream compression scheme verification.'}
    (OUTPUT/'build-report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
    print('MERGE OK: official',len(orig_p['fixes']),'+ BASE',len(base_p['fixes']),'=',len(merged_p['fixes']),'IFix fixes')
    print('Original UnityFS:',len(original),'bytes; merged:',len(result),'bytes; GZIP:',len(packed),'bytes')
    print(row)

if __name__=='__main__': main()
