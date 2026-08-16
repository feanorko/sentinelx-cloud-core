from pathlib import Path


def test_crypto_audit_separates_wire_and_plaintext(tmp_path, monkeypatch):
    wire = tmp_path / "wire.jsonl"
    plain = tmp_path / "plain.jsonl"
    monkeypatch.setenv("SENTINELX_CRYPTO_WIRE_AUDIT_PATH", str(wire))
    monkeypatch.setenv("SENTINELX_CRYPTO_PLAINTEXT_AUDIT_PATH", str(plain))

    # Reload after env setup because paths are module-level configuration.
    import importlib
    import sentinelx_core.crypto_audit as audit
    importlib.reload(audit)

    audit.record_wire("command", "sx1:encrypted-command")
    audit.record_plain("command", "echo hello")
    audit.record_plain("response", "hello\n")
    audit.record_wire("response", "sx1:encrypted-response")

    assert "sx1:encrypted-command" in wire.read_text()
    assert "sx1:encrypted-response" in wire.read_text()
    assert "echo hello" not in wire.read_text()
    assert "hello\\n" not in wire.read_text()
    assert "echo hello" in plain.read_text()
    assert "hello\\n" in plain.read_text()
    assert "sx1:encrypted-command" not in plain.read_text()
