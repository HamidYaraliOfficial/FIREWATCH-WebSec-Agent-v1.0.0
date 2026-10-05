from app.scope import ScopePolicy, ScopeViolation


def test_scope_allows_same_host():
    p = ScopePolicy.from_root("https://example.com/app", allow_private_targets=True)
    assert p.is_allowed("https://example.com/app/page")
    assert not p.is_allowed("https://evil.example/app")


def test_scope_rejects_unsupported_scheme():
    try:
        ScopePolicy.from_root("ftp://example.com")
    except ScopeViolation:
        return
    assert False, "expected scope violation"
