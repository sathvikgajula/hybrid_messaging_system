import sys
import os
import json
import tempfile
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import protocol
import keyfile
import database


class TestProtocol(unittest.TestCase):
    alice = None
    bob = None

    @classmethod
    def setUpClass(cls):
        cls.alice = protocol.generate_user_keys(1024, 512, 512)
        cls.bob = protocol.generate_user_keys(1024, 512, 512)
        cls.alice_pub = protocol.public_keys_from(cls.alice)
        cls.bob_pub = protocol.public_keys_from(cls.bob)

    def _roundtrip(self, scheme):
        payload = protocol.hybrid_encrypt(
            "hello bob", self.alice, self.bob_pub, scheme, "alice", "bob"
        )
        plaintext, ok, reason = protocol.hybrid_decrypt(
            payload, self.bob, self.alice['rsa']['pub'].encode(), expected_recipient="bob"
        )
        self.assertTrue(ok, reason)
        self.assertEqual(plaintext, "hello bob")

    def test_hybrid_rsa(self):
        self._roundtrip("rsa")

    def test_hybrid_elgamal(self):
        self._roundtrip("elgamal")

    def test_hybrid_rabin(self):
        self._roundtrip("rabin")

    def test_verify_before_decrypt_tampered_ciphertext(self):
        payload = protocol.hybrid_encrypt(
            "secret", self.alice, self.bob_pub, "rsa", "alice", "bob"
        )
        payload["ciphertext"] = "AAAA" + payload["ciphertext"][4:]
        plaintext, ok, reason = protocol.hybrid_decrypt(
            payload, self.bob, self.alice['rsa']['pub'].encode(), expected_recipient="bob"
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "bad signature")
        self.assertIsNone(plaintext)

    def test_wrong_recipient_is_rejected(self):
        payload = protocol.hybrid_encrypt(
            "secret", self.alice, self.bob_pub, "rsa", "alice", "bob"
        )
        payload["recipient"] = "mallory"
        plaintext, ok, reason = protocol.hybrid_decrypt(
            payload, self.bob, self.alice['rsa']['pub'].encode(), expected_recipient="bob"
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "wrong recipient")

    def test_identity_binds_username_to_key(self):
        pubs, sig = protocol.sign_identity_bundle("alice", self.alice)
        self.assertTrue(protocol.verify_identity_bundle("alice", pubs, sig))
        self.assertFalse(protocol.verify_identity_bundle("mallory", pubs, sig))

    def test_group_pack_stays_inside_ciphertext(self):
        gid = protocol.new_group_id()
        packed = protocol.pack_group(gid, "Weekend", ["alice", "bob"], "hi", event="invite")
        inner = protocol.parse_inner(packed)
        self.assertEqual(inner["kind"], "group")
        self.assertEqual(inner["members"], ["alice", "bob"])
        self.assertNotEqual(
            protocol.public_fingerprint(self.alice_pub),
            protocol.public_fingerprint(self.bob_pub),
        )

    def test_file_roundtrip_and_filename_sanitized(self):
        packed = protocol.pack_file("../../secret.txt", b"hello-bytes", "text/plain")
        inner = protocol.parse_inner(packed)
        self.assertEqual(inner["kind"], "file")
        self.assertEqual(inner["name"], "secret.txt")
        self.assertEqual(inner["data"], b"hello-bytes")
        payload = protocol.hybrid_encrypt(
            packed, self.alice, self.bob_pub, "rsa", "alice", "bob"
        )
        plaintext, ok, reason = protocol.hybrid_decrypt(
            payload, self.bob, self.alice["rsa"]["pub"].encode(), expected_recipient="bob"
        )
        self.assertTrue(ok, reason)
        again = protocol.parse_inner(plaintext)
        self.assertEqual(again["sha256"], inner["sha256"])
        self.assertEqual(again["data"], b"hello-bytes")

    def test_file_rejects_oversize_and_bad_hash(self):
        with self.assertRaises(ValueError):
            protocol.pack_file("big.bin", b"x" * (protocol.MAX_FILE_BYTES + 1))
        packed = protocol.pack_file("ok.bin", b"abc")
        data = json.loads(packed)
        data["sha256"] = "0" * 64
        self.assertIsNone(protocol.parse_inner(json.dumps(data)))
        data = json.loads(packed)
        data["size"] = True
        self.assertIsNone(protocol.parse_inner(json.dumps(data)))

    def test_call_signal_is_signed_inner_payload(self):
        call_id = protocol.new_call_id()
        sdp = (
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"
            "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n"
            "a=fingerprint:sha-256 AA:BB:CC\r\n"
        )
        packed = protocol.pack_call("offer", call_id, sdp=sdp)
        inner = protocol.parse_inner(packed)
        self.assertEqual(inner["kind"], "call")
        self.assertEqual(inner["event"], "offer")
        self.assertEqual(inner["call_id"], call_id)
        with self.assertRaises(ValueError):
            protocol.pack_call("offer", "nope", sdp=sdp)
        with self.assertRaises(ValueError):
            protocol.pack_call("offer", call_id, sdp=sdp + "m=video 9 UDP/TLS/RTP/SAVPF 96\r\n")
        ice = protocol.pack_call(
            "ice",
            call_id,
            candidate={"candidate": "candidate:0 1 UDP 1 127.0.0.1 9 typ host", "sdpMid": "0", "sdpMLineIndex": 0},
        )
        self.assertEqual(protocol.parse_inner(ice)["event"], "ice")
        bad_ice = json.loads(ice)
        bad_ice["candidate"]["candidate"] = "<script>x</script>"
        self.assertIsNone(protocol.parse_inner(json.dumps(bad_ice)))


class TestKeyfile(unittest.TestCase):
    def test_encrypt_and_reload(self):
        keys = {"rsa": {"priv": "x", "pub": "y"}}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            path = tmp.name
        try:
            keyfile.save_keyfile(path, "alice", keys, "correct horse")
            with open(path) as f:
                blob = json.load(f)
            self.assertEqual(blob["kdf"], "pbkdf2-sha256")
            self.assertNotIn("keys", blob)
            user, loaded, encrypted, state = keyfile.load_keyfile(path, "correct horse")
            self.assertTrue(encrypted)
            self.assertEqual(user, "alice")
            self.assertEqual(loaded, keys)
            self.assertEqual(state, {})
        finally:
            os.unlink(path)

    def test_wrong_passphrase_fails(self):
        keys = {"rsa": {"priv": "x", "pub": "y"}}
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            path = tmp.name
        try:
            keyfile.save_keyfile(path, "alice", keys, "right")
            with self.assertRaises(Exception):
                keyfile.load_keyfile(path, "wrong")
        finally:
            os.unlink(path)


class TestServerAuth(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        cls.tmp.close()
        database.configure(cls.tmp.name)
        from fastapi.testclient import TestClient
        from server import app
        cls.client = TestClient(app)
        cls.alice = protocol.generate_user_keys(1024, 512, 512)
        cls.bob = protocol.generate_user_keys(1024, 512, 512)
        alice_pubs, alice_sig = protocol.sign_identity_bundle("alice", cls.alice)
        bob_pubs, bob_sig = protocol.sign_identity_bundle("bob", cls.bob)
        r1 = cls.client.post("/register", json={
            "username": "alice",
            "public_keys": alice_pubs,
            "identity_sig": alice_sig,
        })
        r2 = cls.client.post("/register", json={
            "username": "bob",
            "public_keys": bob_pubs,
            "identity_sig": bob_sig,
        })
        if r1.status_code != 200 or r2.status_code != 200:
            raise RuntimeError(r1.text + r2.text)

    @classmethod
    def tearDownClass(cls):
        os.unlink(cls.tmp.name)

    def test_inbox_rejects_missing_auth(self):
        resp = self.client.get("/inbox/alice")
        self.assertIn(resp.status_code, (404, 405))

    def test_inbox_rejects_bad_signature(self):
        auth = protocol.inbox_auth_payload("alice", self.alice['rsa']['priv'])
        auth["signature"] = "AAAA"
        resp = self.client.post("/inbox", json=auth)
        self.assertEqual(resp.status_code, 401)

    def test_send_and_authenticated_inbox(self):
        payload = protocol.hybrid_encrypt(
            "hi from tests",
            self.alice,
            protocol.public_keys_from(self.bob),
            "rsa",
            "alice",
            "bob",
        )
        send = self.client.post("/send", json={
            "sender": "alice",
            "recipient": "bob",
            "payload": payload,
        })
        self.assertEqual(send.status_code, 200, send.text)
        auth = protocol.inbox_auth_payload("bob", self.bob['rsa']['priv'])
        inbox = self.client.post("/inbox", json=auth)
        self.assertEqual(inbox.status_code, 200)
        messages = inbox.json()["messages"]
        self.assertTrue(any(m["payload"]["sender"] == "alice" for m in messages))

    def test_register_rejects_swapped_identity(self):
        mallory = protocol.generate_user_keys(1024, 512, 512)
        pubs, sig = protocol.sign_identity_bundle("mallory", mallory)
        # Bind the signature to mallory, then try to publish it as eve
        resp = self.client.post("/register", json={
            "username": "eve",
            "public_keys": pubs,
            "identity_sig": sig,
        })
        self.assertEqual(resp.status_code, 400)

    def test_keys_endpoint_returns_verifiable_bundle(self):
        resp = self.client.get("/keys/alice")
        self.assertEqual(resp.status_code, 200)
        bundle = resp.json()
        self.assertTrue(protocol.verify_identity_bundle(
            "alice", bundle["public_keys"], bundle["identity_sig"]
        ))

    def test_register_requires_invite_when_configured(self):
        from unittest.mock import patch
        mallory = protocol.generate_user_keys(1024, 512, 512, rsa_only=True)
        pubs, sig = protocol.sign_identity_bundle("zoe", mallory)
        with patch.dict(os.environ, {"SEALED_INVITE": "correct-horse-invite"}):
            denied = self.client.post("/register", json={
                "username": "zoe",
                "public_keys": pubs,
                "identity_sig": sig,
            })
            self.assertEqual(denied.status_code, 403)
            ok = self.client.post("/register", json={
                "username": "zoe",
                "public_keys": pubs,
                "identity_sig": sig,
                "invite": "correct-horse-invite",
            })
            self.assertEqual(ok.status_code, 200, ok.text)

    def test_ice_requires_inbox_auth(self):
        resp = self.client.post("/ice", json={})
        self.assertIn(resp.status_code, (401, 422))
        auth = protocol.inbox_auth_payload("alice", self.alice["rsa"]["priv"])
        from unittest.mock import patch
        with patch.dict(os.environ, {"SEALED_TURN_HOST": "sealed.example.com", "SEALED_TURN_SECRET": "s" * 24}):
            iced = self.client.post("/ice", json=auth)
        self.assertEqual(iced.status_code, 200, iced.text)
        urls = [s["urls"] for s in iced.json()["iceServers"]]
        self.assertTrue(any(u.startswith("stun:") for u in urls))
        self.assertTrue(any(u.startswith("turn:") for u in urls))


class TestNetconfig(unittest.TestCase):
    def test_localhost_http_allowed(self):
        import netconfig
        netconfig.assert_safe_urls("http://127.0.0.1:8000", "ws://127.0.0.1:8000/ws")

    def test_public_http_rejected(self):
        import netconfig
        with self.assertRaises(ValueError):
            netconfig.assert_safe_urls("http://example.com", "ws://example.com/ws")

    def test_unfrozen_defaults_to_localhost(self):
        import netconfig
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            with patch.object(netconfig, "app_dir", return_value=d), \
                    patch.object(sys, "frozen", False, create=True), \
                    patch.dict(os.environ, {}, clear=True):
                http, ws = netconfig.load_relay_urls()
        self.assertEqual(http, "http://127.0.0.1:8000")
        self.assertEqual(ws, "ws://127.0.0.1:8000/ws")

    def test_frozen_uses_bundled_example(self):
        import netconfig
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "sealed.example.json"), "w", encoding="utf-8") as f:
                json.dump({"relay": "https://saled-max.duckdns.org"}, f)
            with patch.object(netconfig, "app_dir", return_value=d), \
                    patch.object(netconfig, "resource_dir", return_value=d), \
                    patch.object(sys, "frozen", True, create=True), \
                    patch.dict(os.environ, {}, clear=True):
                http, ws = netconfig.load_relay_urls()
        self.assertEqual(http, "https://saled-max.duckdns.org")
        self.assertEqual(ws, "wss://saled-max.duckdns.org/ws")

    def test_rsa_only_identity_roundtrip(self):
        keys = protocol.generate_user_keys(1024, rsa_only=True)
        pubs, sig = protocol.sign_identity_bundle("carol", keys)
        self.assertTrue(protocol.verify_identity_bundle("carol", pubs, sig))
        self.assertNotIn("elgamal", pubs)
        payload = protocol.hybrid_encrypt(
            "hi", keys, pubs, "rsa", "carol", "carol"
        )
        # encrypting to self is allowed by the crypto layer
        plaintext, ok, reason = protocol.hybrid_decrypt(
            payload, keys, pubs["rsa"].encode(), expected_recipient="carol"
        )
        self.assertTrue(ok, reason)
        self.assertEqual(plaintext, "hi")


class TestGroupRoster(unittest.TestCase):
    def setUp(self):
        import client_gui
        self.m = client_gui.Messenger()
        self.m.username = "alice"
        self.m.state = {"tofu": {}, "chats": {}, "seen": []}

    def _group(self, gid, members, creator="alice"):
        cid = f"grp:{gid}"
        self.m.state["chats"][cid] = {
            "type": "group",
            "group_id": gid,
            "title": "G",
            "members": members,
            "creator": creator,
            "messages": [],
            "updated": 0,
        }
        return cid

    def test_non_creator_cannot_add_eavesdropper(self):
        gid = protocol.new_group_id()
        cid = self._group(gid, ["alice", "mallory"], creator="alice")
        inner = {
            "kind": "group",
            "event": "update",
            "group_id": gid,
            "title": "G",
            "members": ["alice", "mallory", "eve"],
            "text": "",
        }
        self.m._ingest_group("mallory", inner, "rsa")
        self.assertEqual(self.m.state["chats"][cid]["members"], ["alice", "mallory"])

    def test_creator_can_update_members(self):
        gid = protocol.new_group_id()
        cid = self._group(gid, ["alice", "mallory"], creator="alice")
        inner = {
            "kind": "group",
            "event": "update",
            "group_id": gid,
            "title": "G",
            "members": ["alice", "mallory", "eve"],
            "text": "",
        }
        self.m._ingest_group("alice", inner, "rsa")
        self.assertEqual(self.m.state["chats"][cid]["members"], ["alice", "mallory", "eve"])


class TestClientIp(unittest.TestCase):
    def test_trust_proxy_uses_last_hop(self):
        from unittest.mock import MagicMock, patch
        import server
        req = MagicMock()
        req.headers.get.side_effect = lambda k, d="": {
            "x-forwarded-for": "1.1.1.1, 9.9.9.9",
            "x-real-ip": "",
        }.get(k, d)
        req.client.host = "127.0.0.1"
        with patch.dict(os.environ, {"SEALED_TRUST_PROXY": "1"}):
            self.assertEqual(server._client_ip(req), "9.9.9.9")

    def test_without_proxy_uses_socket_peer(self):
        from unittest.mock import MagicMock, patch
        import server
        req = MagicMock()
        req.headers.get.return_value = "1.1.1.1"
        req.client.host = "10.0.0.8"
        with patch.dict(os.environ, {"SEALED_TRUST_PROXY": "0"}):
            self.assertEqual(server._client_ip(req), "10.0.0.8")


if __name__ == '__main__':
    unittest.main()
