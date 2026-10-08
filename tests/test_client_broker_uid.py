"""FINDING-T42-1 / FINDING-2: the client refuses a process that is not the expected broker,
before sending anything. Opt-in (SYNTHE_BROKER_UID / expected_broker_uid): with no expected
uid there is nothing to check against and behaviour is unchanged."""
import json
import os
import shutil
import socket
import tempfile
import threading

import pytest
from test_isolation import daemon
from world import World

import synthe_client as scl


@pytest.fixture
def w(tmp_path):
    return World(tmp_path)


def _fake_broker():
    """A listener that records whatever the client sends, and answers a canned hello."""
    d = tempfile.mkdtemp(prefix="syfake", dir="/tmp")
    got, ready = [], threading.Event()

    def serve():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(os.path.join(d, "broker.sock"))
        srv.listen(1)
        srv.settimeout(10)
        ready.set()
        try:
            conn, _ = srv.accept()
            conn.settimeout(3)
            try:
                data = conn.makefile("rb").readline()
            except OSError:
                data = b""
            if data:
                got.append(json.loads(data))
                conn.sendall(json.dumps({"ok": True, "result": {"isolation": {"mode": "user"}}}).encode() + b"\n")
            conn.close()
        except OSError:
            pass
        finally:
            srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    assert ready.wait(5)
    return d, got, t


def test_control_without_a_pin_the_client_talks_to_a_fake_broker():
    d, got, t = _fake_broker()
    try:
        out = scl.BrokerClient(f"unix://{d}/broker.sock").call("hello")
        assert out["isolation"]["mode"] == "user" and got and got[0]["op"] == "hello"
    finally:
        t.join(5)
        shutil.rmtree(d, ignore_errors=True)


def test_pinned_client_refuses_a_fake_broker_before_sending_anything():
    d, got, t = _fake_broker()
    try:
        c = scl.BrokerClient(f"unix://{d}/broker.sock", expected_broker_uid=os.geteuid() + 1)
        with pytest.raises(scl.BrokerError) as e:
            c.call("claim", packet={"secret": "claim-token-material"})
        assert e.value.code == "broker_not_isolated"
        t.join(5)
        assert got == [], "the client sent a request to the wrong process"
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_pinned_client_accepts_the_real_broker_uid(w):
    with daemon(w.cfg) as url:
        assert scl.BrokerClient(url, expected_broker_uid=os.geteuid()).call("hello")
        with pytest.raises(scl.BrokerError) as e:
            scl.BrokerClient(url, expected_broker_uid=os.geteuid() + 1).call("hello")
        assert e.value.code == "broker_not_isolated"


def test_env_var_pins_the_uid(w, monkeypatch):
    monkeypatch.setenv("SYNTHE_BROKER_UID", str(os.geteuid() + 1))
    with daemon(w.cfg) as url:
        with pytest.raises(scl.BrokerError) as e:
            scl.BrokerClient(url).call("hello")
        assert e.value.code == "broker_not_isolated"


def test_a_pin_over_tcp_fails_closed_not_silently():
    with pytest.raises(scl.BrokerError) as e:
        scl.BrokerClient("tcp://127.0.0.1:9", expected_broker_uid=1000)
    assert e.value.code == "broker_unset"


def test_bad_uid_is_rejected():
    with pytest.raises(scl.BrokerError) as e:
        scl.BrokerClient("unix:///tmp/x.sock", expected_broker_uid="root")
    assert e.value.code == "broker_unset"
