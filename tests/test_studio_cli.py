import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/"src"))
import json
import synthe_studio

def test_demo_once_is_credential_free(capsys,monkeypatch):
 class ExplodingClient:
  def __init__(self,*a,**k): raise AssertionError("demo must not create a broker client")
 monkeypatch.setattr(synthe_studio.scl,"BrokerClient",ExplodingClient)
 assert synthe_studio.main(["--demo","--once"])==0
 out=capsys.readouterr().out
 assert "SAMPLE" in out and "agent/filter-table" in out

def test_demo_json(capsys):
 assert synthe_studio.main(["--demo","--json"])==0
 d=json.loads(capsys.readouterr().out)
 assert d["mode"]=="sample" and d["schema_version"]==1

def test_approval_handoff_uses_argument_array(monkeypatch):
 seen={}
 monkeypatch.setattr(synthe_studio.shutil,"which",lambda _:"/venv/bin/synthe-approve")
 monkeypatch.setattr(synthe_studio.subprocess,"run",lambda args,check: seen.update(args=args,check=check) or type("P",(),{"returncode":0})())
 assert synthe_studio.run_approval("unix:///tmp/broker.sock","task/push_branch")==0
 assert seen["args"]==["/venv/bin/synthe-approve","--broker","unix:///tmp/broker.sock","--id","task/push_branch"] and seen["check"] is False
