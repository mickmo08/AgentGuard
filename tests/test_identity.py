"""Users, roles, sessions, invitations, API tokens and tenant isolation."""
from tests.conftest import PASSWORD


def test_signup_disabled_by_default(make_env):
    env = make_env()
    env.settings.allow_signup = False
    r = env.call("POST", "/v1/auth/signup", who=None, json={"organization": "X", "email": "x@x.com", "password": PASSWORD})
    assert r.status_code == 403


def test_new_org_gets_starter_policy_and_owner(env):
    me = env.ok("GET", "/v1/auth/me")
    assert me["role"] == "owner" and me["org"]["name"] == "Acme"
    active = env.ok("GET", "/v1/admin/policies/active")
    assert active["version"] == 1 and "payments.refund" in active["actions"]


def test_login_logout_and_bad_password(env):
    assert env.call("POST", "/v1/auth/login", who=None, json={"email": "owner@acme.com", "password": "wrong password!!"}).status_code == 401
    assert env.call("POST", "/v1/auth/login", who=None, json={"email": "nobody@acme.com", "password": PASSWORD}).status_code == 401
    token = env.ok("POST", "/v1/auth/login", who=None, json={"email": "OWNER@acme.com", "password": PASSWORD})["token"]
    env.tokens["s2"] = token
    assert env.call("GET", "/v1/auth/me", who="s2").status_code == 200
    assert env.call("POST", "/v1/auth/logout", who="s2").status_code == 204
    assert env.call("GET", "/v1/auth/me", who="s2").status_code == 401


def test_login_throttle(env):
    for _ in range(5):
        env.call("POST", "/v1/auth/login", who=None, json={"email": "owner@acme.com", "password": "nope nope nope"})
    r = env.call("POST", "/v1/auth/login", who=None, json={"email": "owner@acme.com", "password": PASSWORD})
    assert r.status_code == 429  # locked even with the right password


def test_weak_password_rejected(env):
    r = env.call("POST", "/v1/auth/signup", who=None, json={"organization": "B", "email": "b@b.com", "password": "short"})
    assert r.status_code == 422


def test_role_enforcement(env):
    env.add_member("vic", "viewer")
    env.add_member("abe", "approver")
    assert env.call("GET", "/v1/admin/overview", who="vic").status_code == 200
    assert env.call("POST", "/v1/admin/agents", who="vic", json={"slug": "x-bot"}).status_code == 403
    assert env.call("POST", "/v1/admin/agents", who="abe", json={"slug": "x-bot"}).status_code == 403
    assert env.call("GET", "/v1/admin/secrets", who="abe").status_code == 403
    assert env.call("POST", "/v1/admin/policies", who="abe", json={"source": "{}"}).status_code == 403


def test_cannot_grant_above_own_role_or_remove_last_owner(env):
    env.add_member("ada", "admin")
    me = env.ok("GET", "/v1/admin/members")
    owner_id = next(m["id"] for m in me if m["role"] == "owner")
    assert env.call("POST", "/v1/admin/invitations", who="ada", json={"email": "z@acme.com", "role": "owner"}).status_code == 403
    assert env.call("PATCH", f"/v1/admin/members/{owner_id}", who="ada", json={"role": "viewer"}).status_code == 403
    assert env.call("PATCH", f"/v1/admin/members/{owner_id}", json={"role": "admin"}).status_code == 409
    assert env.call("DELETE", f"/v1/admin/members/{owner_id}").status_code == 409


def test_invitation_single_use(env):
    inv = env.ok("POST", "/v1/admin/invitations", json={"email": "new@acme.com", "role": "approver"})
    assert inv["accept_url"].startswith("https://agentguard.test/#/accept-invite?token=")
    env.ok("POST", "/v1/auth/accept-invite", who=None, json={"token": inv["token"], "password": PASSWORD})
    assert env.call("POST", "/v1/auth/accept-invite", who=None, json={"token": inv["token"], "password": PASSWORD}).status_code == 404


def test_removed_member_loses_access(env):
    env.add_member("abe", "approver")
    uid = next(m["id"] for m in env.ok("GET", "/v1/admin/members") if m["email"] == "abe@acme.com")
    env.ok("DELETE", f"/v1/admin/members/{uid}", status=204)
    assert env.call("GET", "/v1/admin/overview", who="abe").status_code == 401


def test_api_tokens_scoped_and_revocable(env):
    tok = env.ok("POST", "/v1/admin/tokens", json={"name": "ci", "role": "admin"})
    env.tokens["ci"] = tok["token"]
    assert env.call("POST", "/v1/admin/agents", who="ci", json={"slug": "ci-bot"}).status_code == 201
    env.ok("DELETE", f"/v1/admin/tokens/{tok['id']}", status=204)
    assert env.call("GET", "/v1/admin/overview", who="ci").status_code == 401


def test_password_change_signs_out_other_sessions(env):
    env.tokens["other"] = env.ok("POST", "/v1/auth/login", who=None, json={"email": "owner@acme.com", "password": PASSWORD})["token"]
    env.ok("POST", "/v1/auth/password", json={"current_password": PASSWORD, "new_password": "a brand new passphrase"}, status=204)
    assert env.call("GET", "/v1/auth/me", who="other").status_code == 401
    assert env.call("GET", "/v1/auth/me").status_code == 200


def test_tenant_isolation(env):
    """Nothing in one organization is visible or usable from another."""
    agent_a = env.agent("support-bot")
    act = env.refund(agent_a, 200)
    r = env.call("POST", "/v1/auth/signup", who=None, json={"organization": "Globex", "email": "eve@globex.com", "password": PASSWORD})
    env.tokens["eve"] = r.json()["token"]
    assert env.call("GET", f"/v1/admin/actions/{act['id']}", who="eve").status_code == 404
    assert env.call("POST", f"/v1/admin/approvals/{act['id']}", who="eve", json={"decision": "approve"}).status_code == 404
    assert env.ok("GET", "/v1/admin/actions", who="eve") == []
    assert env.ok("GET", "/v1/admin/agents", who="eve") == []
    a_agent_id = env.ok("GET", "/v1/admin/agents")[0]["id"]
    assert env.call("POST", f"/v1/admin/agents/{a_agent_id}/pause", who="eve", json={}).status_code == 404
    # Globex's agent cannot read Acme's action, and each org's audit chain is independent.
    agent_g = {"Authorization": f"Bearer {env.ok('POST', '/v1/admin/agents', who='eve', json={'slug': 'support-bot'})['api_key']}"}
    assert env.client.get(f"/v1/actions/{act['id']}", headers=agent_g).status_code == 404
    assert env.ok("GET", "/v1/admin/audit/verify", who="eve")["valid"]
    assert env.call("POST", "/v1/auth/switch-org", who="eve", json={"organization_id": env.ok("GET", "/v1/auth/me")["org"]["id"]}).status_code == 404


def test_user_with_two_orgs_can_switch(env):
    org2 = env.ok("POST", "/v1/organizations", json={"name": "Side Project"}, status=201)
    env.ok("POST", "/v1/auth/switch-org", json={"organization_id": org2["id"]})
    me = env.ok("GET", "/v1/auth/me")
    assert me["org"]["id"] == org2["id"] and len(me["organizations"]) == 2
