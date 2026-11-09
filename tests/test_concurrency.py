"""The org-row lock must keep the audit chain gap-free and approvals single-shot under concurrency."""
from concurrent.futures import ThreadPoolExecutor


def test_concurrent_submissions_keep_audit_chain_intact(env):
    agents = [env.agent(f"support-{i}") for i in range(4)]

    def submit(i: int) -> int:
        r = env.act(agents[i % 4], "payments.get_customer", {"customer_id": "cus_alice"})
        return r.status_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        codes = list(pool.map(submit, range(40)))
    assert codes == [200] * 40
    v = env.ok("GET", "/v1/admin/audit/verify")
    assert v["valid"], v
    executed = env.ok("GET", "/v1/admin/actions?status=executed&limit=500")
    assert len(executed) == 40


def test_simultaneous_approvals_execute_exactly_once(env):
    env.add_member("ada", "admin")
    a = env.agent()
    for _ in range(5):
        req = env.refund(a, 200)  # needs one approval

        def approve(who: str, request_id: str = req["id"]) -> int:
            return env.call("POST", f"/v1/admin/approvals/{request_id}", who=who, json={"decision": "approve"}).status_code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(approve, ["owner", "ada"]))
        assert sorted(results) == [200, 409], results
    assert len(env.mocks.refunds) == 5
    assert env.ok("GET", "/v1/admin/audit/verify")["valid"]
