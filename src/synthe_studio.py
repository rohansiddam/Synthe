# SPDX-License-Identifier: Apache-2.0
"""Synthe Mini Studio terminal review desk."""
from __future__ import annotations
import argparse,json,shutil,subprocess,sys
from pathlib import Path
import synthe_client as scl
import synthe_studio_model as sm

def _sample():
    p=Path(__file__).resolve().parent.parent/"examples"/"studio-demo"/"sample.json"
    x=json.loads(p.read_text(encoding="utf-8")); return x["hello"],x["staged"],x["receipts"]

def observe(broker):
    c=scl.BrokerClient(broker,timeout=5.0)
    return sm.normalize_snapshot(c.call("hello"),c.call("staged"),c.call("receipts",limit=20))

def detail(broker,pid):
    return scl.BrokerClient(broker,timeout=10.0).call("staged_detail",id=pid)

def _approval_command(broker,pid):
    exe=shutil.which("synthe-approve"); a=[exe or sys.executable]
    if not exe: a+=["-m","synthe_approve"]
    if broker: a+=["--broker",broker]
    return a+["--id",pid]

def run_approval(broker,pid):
    return subprocess.run(_approval_command(broker,pid),check=False).returncode

def _snapshot(broker,demo):
    return sm.normalize_snapshot(*_sample(),mode="sample") if demo else observe(broker)

def _print(s,demo,json_mode=False):
    print(json.dumps(s,indent=2,sort_keys=True,ensure_ascii=False) if json_mode else sm.render_snapshot(s,demo))

def main(argv=None):
    ap=argparse.ArgumentParser(description="Synthe Mini Studio — OpenClaw developer preview.")
    ap.add_argument("--broker"); ap.add_argument("--demo",action="store_true")
    ap.add_argument("--once",action="store_true"); ap.add_argument("--json",action="store_true")
    ap.add_argument("command",nargs="?",choices=("check",))
    a=ap.parse_args(argv)
    if a.once and a.json: ap.error("--once and --json are mutually exclusive")
    try: s=_snapshot(a.broker,a.demo)
    except scl.BrokerError as e:
        if not(a.once or a.json or a.command=="check"):
            print(f"synthe-studio: {e.code}: {e.message}",file=sys.stderr); return 2
        s=sm.normalize_snapshot(None,None,None); s["connection"]["error"]={"code":e.code,"message":sm.clean(e.message,True)}
    if a.json:
        _print(s,a.demo,True); return 0 if s["connection"]["status"]=="connected" or a.demo else 2
    if a.once or a.command=="check" or not sys.stdin.isatty():
        _print(s,a.demo); return 0 if s["connection"]["status"]=="connected" or a.demo else 2
    while True:
        print("\033[2J\033[H",end=""); _print(s,a.demo); print("\n[r] refresh   [number] review   [q] quit")
        try: x=input("> ").strip().lower()
        except (EOFError,KeyboardInterrupt): print(); return 0
        if x=="q": return 0
        if x=="r":
            try: s=_snapshot(a.broker,a.demo)
            except scl.BrokerError as e:
                s=sm.normalize_snapshot(None,None,None); s["connection"]["error"]={"code":e.code,"message":sm.clean(e.message,True)}
            continue
        if x.isdigit() and 1<=int(x)<=len(s["proposals"]):
            p=s["proposals"][int(x)-1]
            if a.demo: print("\nSAMPLE — no real approval is possible."); input("Press Enter..."); continue
            try: d=detail(a.broker,p["id"])
            except scl.BrokerError as e: print(f"\nCannot refresh proposal: {e}"); input("Press Enter..."); continue
            print(sm.render_detail(d)); print("\n[a] open exact approval flow   [b] back")
            try: y=input("> ").strip().lower()
            except (EOFError,KeyboardInterrupt): return 0
            if y=="a":
                try: rc=run_approval(a.broker,p["id"])
                except OSError as e: print(f"Could not launch synthe-approve: {e}"); rc=2
                print(f"\nsynthe-approve exited {rc}; refreshing. Exit code is not execution proof.")
                try: s=_snapshot(a.broker,False)
                except scl.BrokerError: s=sm.normalize_snapshot(None,None,None)
                input("Press Enter...")
            continue
        print("Choose a visible proposal number, r, or q.")

if __name__=="__main__": raise SystemExit(main())
