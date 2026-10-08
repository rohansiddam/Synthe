import datetime as dt
import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from world import World, cm, hc, ss, ts, codes
import synthe_lane_templates as lanes
from test_speculative import speculative_claim

@pytest.fixture
def w(tmp_path):
    w = World(tmp_path)
    w.cfg.raw['lane_templates'] = {'receivers': ['builder']}
    return w

def grant(w, **updates):
    x = {'template_id':'lane-1', 'receiver':'builder','tool':'git_push',
         'params':{'remote':'origin','branch_pattern':'feature/*'}, 'path_scope':['src/**'],
         'max_uses':2,'expires_at':ts(dt.timedelta(days=1)), 'lineage':lanes.lineage(w.cfg,w.registry,'builder')}
    x.update(updates)
    return lanes.sign(x,w.keys['rishab'])

def push(w, key='a', branch='feature/a', files=None):
    p=w.packet(idem=key,branch=branch,approve=False)
    tok=speculative_claim(w,p)
    sha=w.commit(files or {'src/app.py':key},msg=key)
    return w.propose(p,tok,sha,branch=branch)

def test_grant_executes_without_per_task_approval(w):
    lanes.submit(w.cfg,grant(w))
    r=push(w)
    assert r['decision']=='executed', r
    assert r['lane_template']['use']==1
    assert lanes.view(w.cfg)['templates'][0]['uses_left']==1

def test_no_grant_still_needs_approval(w):
    assert 'approval_missing' in codes(push(w))

def test_actual_paths_not_agent_declared_paths(w):
    lanes.submit(w.cfg,grant(w))
    r=push(w,files={'tests/outside.py':'no'})
    assert r['decision']=='denied' and 'template_scope' in codes(r)
    assert lanes.view(w.cfg)['templates'][0]['uses_left']==2

def test_revoked_and_exhausted_cannot_execute(w):
    lanes.submit(w.cfg,grant(w,max_uses=1))
    assert push(w)['decision']=='executed'
    assert push(w,'b','feature/b')['decision']=='denied'
    x=lanes.sign({'template_id':'lane-1'},w.keys['rishab'],True)
    lanes.revoke(w.cfg,x)
    assert lanes.view(w.cfg)['templates'][0]['status']=='template_revoked'
    with pytest.raises(cm.Deny): lanes.submit(w.cfg,grant(w))

def test_signature_and_lineage(w):
    x=grant(w); x['max_uses']=100
    with pytest.raises(cm.Deny,match='signature'): lanes.submit(w.cfg,x)
    x=grant(w); lanes.submit(w.cfg,x)
    w.registry['agents']['builder']['policy']['forbidden_paths'].append('src/new/**')
    w.save_registry()
    assert lanes.select(w.cfg,w.registry,'builder',{'remote':'origin','branch':'feature/x'}) is None

def test_reserve_is_serial_bounded_and_durable(w):
    lanes.submit(w.cfg,grant(w,max_uses=3))
    def reserve(_):
        try:
            with lanes.locked(w.cfg):
                return lanes.reserve(w.cfg,'builder',{'remote':'origin','branch':'feature/x'},['src/app.py'],'lane-1')['use']
        except cm.Deny: return None
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(reserve,range(12)))
    assert sorted(x for x in results if x) == [1,2,3]
    assert lanes.load(w.cfg)['uses']['lane-1']==3

def test_expiry_rechecked_after_prepare(w,monkeypatch):
    lanes.submit(w.cfg,grant(w))
    original=cm.GitPush.prepare
    def prepare(*a,**kw):
        result=original(*a,**kw)
        lanes.revoke(w.cfg,lanes.sign({'template_id':'lane-1'},w.keys['rishab'],True))
        return result
    monkeypatch.setattr(cm.GitPush,'prepare',prepare)
    r=push(w)
    assert 'template_revoked' in codes(r)

def test_unrelated_agent_does_not_stale_lane(w):
    x=grant(w); lanes.submit(w.cfg,x)
    w.registry['agents']['other']={'role':'receiver'}
    assert x['lineage']==lanes.lineage(w.cfg,w.registry,'builder')

def test_disabled_integrator_and_corrupt_store(w):
    with pytest.raises(cm.Deny): lanes.submit(w.cfg,grant(w,receiver='claude'))
    lanes.path(w.cfg).parent.mkdir(exist_ok=True)
    lanes.path(w.cfg).write_text('{broken')
    with pytest.raises(cm.Deny,match='store corrupt'): lanes.view(w.cfg)
