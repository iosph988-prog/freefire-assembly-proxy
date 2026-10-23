"""Windows-friendly mitmdump launcher: intercept only game asset CDN domains."""
from __future__ import annotations
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
# Restrict TLS interception to game hot-update domains; other connections
# (including login and Apple) stay encrypted end-to-end and pass through.
# Supports core-bs.freefiremobile.com and dl.gmc.freefiremobile.com etc.
ASSET_CDN_RE = r'(?i)^(?:core|dl)[.-][a-z0-9-]+\.freefiremobile\.com(?::443)?$'

def main():
    parser=argparse.ArgumentParser(description='Serve only the iOS 1.132.10 codepatch asset.')
    parser.add_argument('--host',default='0.0.0.0')
    parser.add_argument('--port',type=int,default=7777)
    args=parser.parse_args()
    exe=shutil.which('mitmdump')
    if not exe:
        folder=Path(sys.executable).parent
        candidates=[folder/('mitmdump.exe' if os.name=='nt' else 'mitmdump'),folder/'Scripts'/'mitmdump.exe',folder/'bin'/'mitmdump']
        for candidate in candidates:
            if candidate.is_file(): exe=str(candidate); break
    if not exe:
        sys.exit('mitmdump missing: py -m pip install -r requirements.txt')
    cmd=[exe,'--mode','regular','--listen-host',args.host,'--listen-port',str(args.port),
         '--allow-hosts',ASSET_CDN_RE,'-s',str(ROOT/'assembly_proxy.py')]
    print(f'Assembly-only proxy listening {args.host}:{args.port}',flush=True)
    print('Only core-*/dl-* freefiremobile.com TLS connections will be intercepted.',flush=True)
    print('All other HTTPS connections pass as unmodified encrypted tunnels.',flush=True)
    try: subprocess.run(cmd,check=True)
    except KeyboardInterrupt: pass

if __name__=='__main__':main()
