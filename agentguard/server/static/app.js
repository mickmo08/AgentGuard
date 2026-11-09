/* AgentGuard dashboard. No build step, no dependencies.
 * Every DOM node is created with h(); text is always inserted as text nodes,
 * so agent-supplied strings (params, context, reasons) cannot inject markup. */
"use strict";
(() => {
  // ------------------------------------------------------------------ utils
  const SVGNS = "http://www.w3.org/2000/svg";
  function h(tag, attrs, ...children) {
    const el = tag.startsWith("svg:") ? document.createElementNS(SVGNS, tag.slice(4)) : document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "class") el.setAttribute("class", v);
      else if (k === "value" && "value" in el) el.value = v;
      else if (k === "checked" || k === "disabled" || k === "selected") el[k] = !!v;
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    const add = (c) => {
      if (c === null || c === undefined || c === false) return;
      if (Array.isArray(c)) return c.forEach(add);
      el.appendChild(c instanceof Node ? c : document.createTextNode(String(c)));
    };
    children.forEach(add);
    return el;
  }
  const store = {
    get: (k) => { try { return sessionStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { sessionStorage.setItem(k, v); } catch {} },
    del: (k) => { try { sessionStorage.removeItem(k); } catch {} },
  };
  const pill = (v, cls) => h("span", { class: `pill ${cls || v}` }, String(v).replace(/_/g, " "));
  const json = (v) => JSON.stringify(v, null, 2);
  const compact = (v) => JSON.stringify(v);
  function ago(iso) {
    if (!iso) return "never";
    const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
    if (s < 0) return "in " + until(iso);
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return new Date(iso).toLocaleDateString();
  }
  function until(iso) {
    const s = Math.round((Date.parse(iso) - Date.now()) / 1000);
    if (s <= 0) return "now";
    if (s < 3600) return `${Math.round(s / 60)}m`;
    return `${Math.round(s / 3600)}h`;
  }
  const when = (iso) => (iso ? new Date(iso).toLocaleString() : "");
  let toastTimer;
  function toast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg; t.classList.add("show");
    clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
  }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); toast("Copied"); } catch { toast("Copy failed; select and copy manually"); }
  }

  // ------------------------------------------------------------------ state
  const S = { token: store.get("ag_session"), me: null, pending: 0, timer: null, signupEnabled: false };
  const ROLE_RANK = { viewer: 0, approver: 1, admin: 2, owner: 3 };
  const can = (role) => S.me && ROLE_RANK[S.me.role] >= ROLE_RANK[role];

  async function api(path, opts = {}) {
    const headers = { "Content-Type": "application/json" };
    if (S.token) headers.Authorization = `Bearer ${S.token}`;
    const res = await fetch(path, { method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined });
    if (res.status === 401 && S.token && !opts.noLogout) { signOut(); throw new Error("Your session ended. Sign in again."); }
    if (res.status === 204) return null;
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error((body.error && body.error.message) || body.detail || `HTTP ${res.status}`);
    return body;
  }
  const guard = (fn) => async (...args) => { try { await fn(...args); } catch (e) { toast(e.message); } };

  // ------------------------------------------------------------------ modal
  function modal(title, body, actions) {
    const overlay = h("div", { class: "overlay", onclick: (e) => { if (e.target === overlay) close(); } });
    const close = () => overlay.remove();
    const foot = h("div", { class: "foot" }, (actions || [{ label: "Close" }]).map((a) =>
      h("button", { class: `btn ${a.cls || ""}`, onclick: guard(async () => { if (a.run) { const keep = await a.run(); if (keep === true) return; } close(); }) }, a.label)));
    overlay.appendChild(h("div", { class: "modal", role: "dialog", "aria-modal": "true" }, h("div", { class: "head" }, title), h("div", { class: "body" }, body), foot));
    document.body.appendChild(overlay);
    const first = overlay.querySelector("input, textarea, select");
    if (first) first.focus();
    return close;
  }
  function showSecretOnce(title, label, secret, extra) {
    modal(title, [
      h("p", { class: "muted" }, label),
      h("div", { class: "secret-once" }, secret),
      h("div", {}, h("button", { class: "btn small", onclick: () => copy(secret) }, "Copy")),
      extra || null,
    ], [{ label: "I've stored it", cls: "primary" }]);
  }

  // ----------------------------------------------------------------- router
  function route() {
    const raw = location.hash.replace(/^#\/?/, "");
    const [path, qs] = raw.split("?");
    return { parts: (path || "overview").split("/").filter(Boolean), query: new URLSearchParams(qs || "") };
  }
  const go = (path) => { location.hash = "#/" + path; };
  window.addEventListener("hashchange", () => render());

  // ------------------------------------------------------------------- auth
  function signOut() {
    if (S.token) api("/v1/auth/logout", { method: "POST", noLogout: true }).catch(() => {});
    S.token = null; S.me = null; store.del("ag_session");
    clearInterval(S.timer);
    render();
  }
  async function loadMe() { S.me = await api("/v1/auth/me"); }
  async function startSession(token) {
    S.token = token; store.set("ag_session", token);
    await loadMe();
    if (route().parts[0] === "accept-invite") go("overview");
    render();
  }

  function authView() {
    const r = route();
    if (r.parts[0] === "accept-invite") return acceptInviteView(r.query.get("token") || "");
    if (r.parts[0] === "signup" && S.signupEnabled) return signupView();
    return loginView();
  }
  function authBox(title, form, footer) {
    return h("div", { class: "auth" }, h("div", { class: "box" },
      h("div", { class: "brand" }, h("span", { class: "logo" }, "◆"), "AgentGuard"),
      h("div", { class: "panel" }, h("div", { class: "head" }, h("h2", {}, title)), h("div", { class: "body" }, form)),
      footer ? h("p", { class: "muted center" }, footer) : null));
  }
  function loginView() {
    const email = h("input", { type: "email", autocomplete: "username", required: true });
    const password = h("input", { type: "password", autocomplete: "current-password", required: true });
    const err = h("div", { class: "notice bad hidden" });
    const submit = guard(async (e) => {
      e.preventDefault(); err.classList.add("hidden");
      try { const r = await api("/v1/auth/login", { method: "POST", body: { email: email.value, password: password.value } }); await startSession(r.token); }
      catch (x) { err.textContent = x.message; err.classList.remove("hidden"); }
    });
    return authBox("Sign in", h("form", { class: "stack", onsubmit: submit },
      h("label", { class: "field" }, "Email", email), h("label", { class: "field" }, "Password", password), err,
      h("button", { class: "btn primary", type: "submit" }, "Sign in")),
      S.signupEnabled ? ["New here? ", h("a", { href: "#/signup" }, "Create an organization")] : "Accounts are created by invitation.");
  }
  function signupView() {
    const org = h("input", { required: true, placeholder: "Acme Inc." });
    const name = h("input", { autocomplete: "name" });
    const email = h("input", { type: "email", autocomplete: "username", required: true });
    const password = h("input", { type: "password", autocomplete: "new-password", required: true, minlength: 12 });
    const err = h("div", { class: "notice bad hidden" });
    const submit = guard(async (e) => {
      e.preventDefault(); err.classList.add("hidden");
      try {
        const r = await api("/v1/auth/signup", { method: "POST", body: { organization: org.value, name: name.value, email: email.value, password: password.value } });
        await startSession(r.token);
      } catch (x) { err.textContent = x.message; err.classList.remove("hidden"); }
    });
    return authBox("Create your organization", h("form", { class: "stack", onsubmit: submit },
      h("label", { class: "field" }, "Organization", org), h("label", { class: "field" }, "Your name", name),
      h("label", { class: "field" }, "Work email", email), h("label", { class: "field" }, "Password (12+ characters)", password), err,
      h("button", { class: "btn primary", type: "submit" }, "Create organization")),
      ["Already have an account? ", h("a", { href: "#/login" }, "Sign in")]);
  }
  function acceptInviteView(token) {
    const name = h("input", { autocomplete: "name" });
    const password = h("input", { type: "password", autocomplete: "new-password", required: true });
    const err = h("div", { class: "notice bad hidden" });
    const submit = guard(async (e) => {
      e.preventDefault(); err.classList.add("hidden");
      try { const r = await api("/v1/auth/accept-invite", { method: "POST", body: { token, name: name.value, password: password.value } }); await startSession(r.token); }
      catch (x) { err.textContent = x.message; err.classList.remove("hidden"); }
    });
    return authBox("Join your team", h("form", { class: "stack", onsubmit: submit },
      h("p", { class: "muted m0" }, "Choose a password (12+ characters). If you already have an AgentGuard account, enter its current password."),
      h("label", { class: "field" }, "Your name", name), h("label", { class: "field" }, "Password", password), err,
      h("button", { class: "btn primary", type: "submit" }, "Accept invitation")));
  }

  // ------------------------------------------------------------------ shell
  const NAV = [
    ["overview", "Overview", "viewer"], ["approvals", "Approvals", "viewer"], ["actions", "Actions", "viewer"], ["agents", "Agents", "viewer"],
    ["policies", "Policies", "viewer"], ["secrets", "Secrets", "admin"], ["integrations", "Integrations", "admin"], ["team", "Team", "viewer"], ["audit", "Audit", "viewer"],
  ];
  function shell(content) {
    const current = route().parts[0];
    const sidebar = h("aside", { class: "sidebar" },
      h("div", { class: "brand" }, h("span", { class: "logo" }, "◆"), "AgentGuard"),
      h("nav", { class: "nav" }, NAV.filter(([, , r]) => can(r)).map(([id, label]) =>
        h("a", { href: `#/${id}`, class: current === id ? "active" : "" }, label,
          id === "approvals" && S.pending ? h("span", { class: "count" }, S.pending) : null))),
      h("div", { class: "foot" },
        h("div", {}, h("div", {}, S.me.user ? S.me.user.email : S.me.token.name), h("div", { class: "faint" }, S.me.role)),
        h("div", { class: "row" }, h("button", { class: "btn small", onclick: changePassword }, "Password"), h("button", { class: "btn small", onclick: signOut }, "Sign out"))));
    const orgSelect = h("select", { "aria-label": "Organization", onchange: guard(async (e) => {
      if (e.target.value === "__new") return newOrg();
      await api("/v1/auth/switch-org", { method: "POST", body: { organization_id: e.target.value } }); await loadMe(); go("overview"); render();
    }) }, S.me.organizations.map((o) => h("option", { value: o.id, selected: o.id === S.me.org.id }, `${o.name} (${o.role})`)), h("option", { value: "__new" }, "+ New organization"));
    const topbar = h("div", { class: "topbar" },
      h("button", { class: "btn small menu-btn", onclick: () => sidebar.classList.toggle("open") }, "Menu"),
      h("div", { class: "grow" }), orgSelect);
    return h("div", { class: "shell" }, sidebar, h("div", { class: "main" }, topbar, h("div", { class: "content", id: "content" }, content)));
  }
  function changePassword() {
    const cur = h("input", { type: "password", autocomplete: "current-password" });
    const nw = h("input", { type: "password", autocomplete: "new-password" });
    modal("Change password", [h("label", { class: "field" }, "Current password", cur), h("label", { class: "field" }, "New password (12+ characters)", nw),
      h("p", { class: "muted" }, "Your other sessions will be signed out.")],
    [{ label: "Cancel" }, { label: "Change password", cls: "primary", run: async () => {
      await api("/v1/auth/password", { method: "POST", body: { current_password: cur.value, new_password: nw.value } }); toast("Password changed");
    } }]);
  }
  function newOrg() {
    const name = h("input", { placeholder: "Organization name" });
    modal("New organization", [h("label", { class: "field" }, "Name", name), h("p", { class: "muted" }, "You'll be its owner. It starts with the starter policy.")],
      [{ label: "Cancel", run: () => render() }, { label: "Create", cls: "primary", run: async () => {
        const org = await api("/v1/organizations", { method: "POST", body: { name: name.value } });
        await api("/v1/auth/switch-org", { method: "POST", body: { organization_id: org.id } }); await loadMe(); go("overview"); render();
      } }]);
  }
  const pageHead = (title, sub, right) => h("div", { class: "page-head spread" }, h("div", {}, h("h1", {}, title), sub ? h("p", {}, sub) : null), right || null);
  const panel = (title, body, right) => h("div", { class: "panel" }, title ? h("div", { class: "head" }, h("h2", {}, title), h("div", { class: "grow" }), right || null) : null, body);
  const empty = (text) => h("div", { class: "empty" }, text);

  // ------------------------------------------------------------ action bits
  function actionsTable(rows, compactView) {
    if (!rows.length) return empty("No actions match.");
    return h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["When", "Agent", "Action", compactView ? null : "Params", "Decision", "Status", "Rule"].filter(Boolean).map((c) => h("th", {}, c)))),
      h("tbody", {}, rows.map((r) => h("tr", { class: "click", onclick: () => go(`actions/${r.id}`) },
        h("td", { class: "muted nowrap", title: when(r.created_at) }, ago(r.created_at)), h("td", { class: "nowrap" }, r.agent_slug),
        h("td", { class: "mono nowrap" }, r.action), compactView ? null : h("td", { class: "mono params", title: compact(r.params) }, compact(r.params)),
        h("td", {}, pill(r.decision)), h("td", {}, pill(r.status)), h("td", { class: "mono faint nowrap" }, r.rule_id || "default"))))));
  }
  function approvalProgress(r) {
    const got = r.approvals.filter((a) => a.decision === "approve").length;
    return h("div", { class: "row" }, h("div", { class: "progress" }, Array.from({ length: r.approvals_required }, (_, i) => h("span", { class: i < got ? "on" : "" }))),
      h("span", { class: "muted" }, `${got} of ${r.approvals_required} approval${r.approvals_required > 1 ? "s" : ""} · ${r.approver_roles.join(", ")}`));
  }
  function approvalCard(r, onDone) {
    const note = h("input", { class: "note", placeholder: "Note (optional, recorded in the audit log)" });
    const decide = (decision) => guard(async () => {
      const res = await api(`/v1/admin/approvals/${encodeURIComponent(r.id)}`, { method: "POST", body: { decision, note: note.value } });
      toast(`${res.action}: ${res.status.replace(/_/g, " ")}`); onDone();
    });
    const reasonCant = !can("approver") ? "Your role can't approve actions." : !r.approver_roles.includes(S.me.role) ? `Needs a ${r.approver_roles.join(" or ")}.`
      : r.approvals.some((a) => a.user === (S.me.user && S.me.user.email)) ? "You've already approved; a different person must give the next approval." : S.me.kind !== "user" ? "API tokens can't approve." : null;
    return h("div", { class: "card" },
      h("div", { class: "spread" }, h("div", { class: "row" }, h("span", { class: "title" }, r.action), pill("review"), h("span", { class: "muted" }, `by ${r.agent_slug} · ${ago(r.created_at)}`)),
        h("span", { class: "muted", title: when(r.expires_at) }, `expires in ${until(r.expires_at)}`)),
      h("dl", { class: "kv" },
        Object.entries(r.params).map(([k, v]) => [h("dt", {}, k), h("dd", {}, compact(v))]),
        h("dt", {}, "why review"), h("dd", {}, r.reason),
        Object.keys(r.context || {}).length ? [h("dt", {}, "agent context"), h("dd", {}, compact(r.context))] : null,
        r.approvals.length ? [h("dt", {}, "votes"), h("dd", {}, r.approvals.map((a) => `${a.user} ${a.decision}d${a.note ? ` ("${a.note}")` : ""}`).join("; "))] : null),
      approvalProgress(r),
      h("div", { class: "row mt" },
        r.can_decide ? [note, h("button", { class: "btn approve", onclick: decide("approve") }, "Approve"), h("button", { class: "btn danger", onclick: decide("deny") }, "Deny")]
          : h("span", { class: "muted grow" }, reasonCant || ""),
        h("button", { class: "btn", onclick: () => go(`actions/${r.id}`) }, "Details")));
  }

  // ------------------------------------------------------------------ views
  function chart(hourly) {
    const max = Math.max(1, ...hourly.map((b) => b.allow + b.review + b.block));
    const W = 24 * 20, H = 120;
    const svg = h("svg:svg", { viewBox: `0 0 ${W} ${H + 16}`, preserveAspectRatio: "none", role: "img", "aria-label": "Actions per hour, last 24 hours" });
    const colors = { allow: "var(--allow)", review: "var(--review)", block: "var(--block)" };
    hourly.forEach((b, i) => {
      let y = H;
      for (const k of ["allow", "review", "block"]) {
        const hgt = (b[k] / max) * H;
        if (hgt > 0) { y -= hgt; svg.appendChild(h("svg:rect", { x: i * 20 + 3, y, width: 14, height: hgt, rx: 2, fill: colors[k] }, h("svg:title", {}, `${new Date(b.hour).getHours()}:00 · ${k}: ${b[k]}`))); }
      }
    });
    svg.appendChild(h("svg:line", { x1: 0, x2: W, y1: H + 0.5, y2: H + 0.5, stroke: "var(--border)" }));
    return h("div", { class: "chart" }, svg, h("div", { class: "legend" }, Object.entries(colors).map(([k, c]) => h("span", {}, h("i", { class: `sw-${k}` }), k))));
  }

  async function overviewView() {
    const [o, pending, recent] = await Promise.all([api("/v1/admin/overview"), api("/v1/admin/approvals"), api("/v1/admin/actions?limit=8")]);
    S.pending = o.pending_approvals;
    const st = o.by_status;
    const tile = (label, value, cls) => h("div", { class: `tile ${cls || ""}` }, h("div", { class: "label" }, label), h("div", { class: "value" }, value));
    return [
      pageHead("Overview", `Last 24 hours · policy v${o.policy_version ?? "–"}`),
      h("div", { class: "tiles" },
        tile("Actions", o.actions), tile("Executed", st.executed || 0), tile("Waiting for approval", o.pending_approvals, o.pending_approvals ? "warn" : ""),
        tile("Blocked or denied", (st.blocked || 0) + (st.denied || 0)), tile("Failed", st.failed || 0, st.failed ? "bad" : ""),
        tile("Unknown outcome", o.unknown_outcomes, o.unknown_outcomes ? "bad" : ""), tile("Agents paused", `${o.agents.paused} / ${o.agents.total}`, o.agents.paused ? "warn" : "")),
      o.unknown_outcomes ? h("div", { class: "notice bad mb" }, `${o.unknown_outcomes} action(s) started but never reported a result. Check the downstream system, then review them under Actions → status "unknown".`) : null,
      h("div", { class: "grid-main-side" },
        h("div", { class: "stack" },
          panel("Decisions per hour", h("div", { class: "body" }, chart(o.hourly))),
          panel("Recent actions", actionsTable(recent, true), h("a", { href: "#/actions" }, "All actions"))),
        h("div", { class: "stack" },
          panel("Waiting for approval", h("div", { class: "body stack" }, pending.length ? pending.slice(0, 3).map((r) => approvalCard(r, render)) : h("span", { class: "muted" }, "Nothing waiting.")),
            pending.length > 3 ? h("a", { href: "#/approvals" }, `All ${pending.length}`) : null),
          panel("Top actions", h("div", { class: "body" }, o.top_actions.length ? h("table", {}, h("tbody", {}, o.top_actions.map(([a, n]) => h("tr", {}, h("td", { class: "mono" }, a), h("td", { class: "right" }, n))))) : h("span", { class: "muted" }, "No traffic yet."))))),
    ];
  }

  async function approvalsView() {
    const pending = await api("/v1/admin/approvals");
    S.pending = pending.length;
    return [pageHead("Approvals", "Actions agents asked to take that policy routed to a person."),
      pending.length ? h("div", { class: "stack" }, pending.map((r) => approvalCard(r, render))) : panel(null, empty("Nothing is waiting for approval."))];
  }

  async function actionsView() {
    const q = route().query;
    const [rows, agents] = await Promise.all([api(`/v1/admin/actions?${new URLSearchParams([...q].filter(([, v]) => v))}&limit=200`), api("/v1/admin/agents")]);
    const setQ = (k, v) => { q.set(k, v); go(`actions?${q}`); };
    const status = h("select", { onchange: (e) => setQ("status", e.target.value) }, ["", "executed", "pending_approval", "blocked", "denied", "failed", "expired", "unknown", "executing"].map((s) =>
      h("option", { value: s, selected: q.get("status") === s }, s ? s.replace(/_/g, " ") : "any status")));
    const agent = h("select", { onchange: (e) => setQ("agent", e.target.value) }, h("option", { value: "" }, "any agent"), agents.map((a) => h("option", { value: a.slug, selected: q.get("agent") === a.slug }, a.slug)));
    return [pageHead("Actions", "Every request an agent made, and what happened to it."),
      h("div", { class: "panel" }, h("div", { class: "head" }, h("div", { class: "row" }, status, agent,
        q.get("run_id") ? h("span", { class: "muted" }, `run ${q.get("run_id")} · `, h("a", { href: "#/actions" }, "clear")) : null)), actionsTable(rows))];
  }

  async function actionDetailView(id) {
    const a = await api(`/v1/admin/actions/${encodeURIComponent(id)}`);
    const kv = (pairs) => h("dl", { class: "kv" }, pairs.filter(Boolean).map(([k, v]) => [h("dt", {}, k), h("dd", {}, v)]));
    return [
      h("p", {}, h("a", { href: "#/actions" }, "← Actions")),
      pageHead(a.action, `${a.agent_slug} · ${when(a.created_at)}`, h("div", { class: "row" }, pill(a.decision), pill(a.status))),
      a.status === "unknown" ? h("div", { class: "notice bad mb" }, a.error) : null,
      h("div", { class: "grid-main-side" },
        h("div", { class: "stack" },
          a.status === "pending_approval" ? approvalCard(a, render) : null,
          panel("Request", h("div", { class: "body" }, h("pre", {}, json(a.params)),
            Object.keys(a.context || {}).length ? [h("h3", {}, "Agent context"), h("pre", {}, json(a.context))] : null)),
          a.result ? panel("Result", h("div", { class: "body" }, h("pre", {}, json(a.result)))) : null,
          a.error && a.status !== "unknown" ? panel("Error", h("div", { class: "body" }, h("div", { class: "notice bad" }, a.error))) : null,
          panel("Timeline", h("div", { class: "body" }, h("ol", { class: "timeline" }, a.timeline.map((e) => h("li", {},
            h("div", {}, h("span", { class: "ev" }, e.event_type), h("span", { class: "muted" }, ` · ${e.actor} · ${new Date(e.ts).toLocaleTimeString()}`)),
            Object.keys(e.data).length ? h("pre", {}, json(e.data)) : null)))))),
        panel("Details", h("div", { class: "body" }, kv([
          ["request", a.id], ["agent", a.agent_slug], ["decision", `${a.decision} · ${a.rule_id || "default"}`], ["reason", a.reason],
          ["policy", a.policy_version != null ? `v${a.policy_version}` : "–"], a.run_id && ["run", h("a", { href: `#/actions?run_id=${encodeURIComponent(a.run_id)}` }, a.run_id)],
          ["idempotency", a.idempotency_key], a.approvals_required && ["approvals", `${a.approvals.filter((v) => v.decision === "approve").length} of ${a.approvals_required}`],
          ...a.approvals.map((v) => [`${v.decision} (${v.via})`, `${v.user} · ${when(v.at)}${v.note ? ` · ${v.note}` : ""}`]),
          a.duration_ms != null && ["duration", `${a.duration_ms} ms`], a.executed_at && ["finished", when(a.executed_at)]])))),
    ];
  }

  async function agentsView() {
    const agents = await api("/v1/admin/agents");
    const act = (path, body, msg) => guard(async () => { await api(path, { method: "POST", body: body || {} }); toast(msg); render(); });
    const create = () => {
      const f = { slug: h("input", { placeholder: "support-bot" }), name: h("input", { placeholder: "Support bot" }), owner: h("input", { placeholder: "cx-team" }),
        environment: h("select", {}, ["production", "staging", "development"].map((e) => h("option", { value: e }, e))) };
      modal("Register an agent", [h("label", { class: "field" }, "ID (what policies match on)", f.slug), h("label", { class: "field" }, "Display name", f.name),
        h("label", { class: "field" }, "Owner / team", f.owner), h("label", { class: "field" }, "Environment", f.environment)],
      [{ label: "Cancel" }, { label: "Create", cls: "primary", run: async () => {
        const r = await api("/v1/admin/agents", { method: "POST", body: { slug: f.slug.value.trim(), name: f.name.value, owner: f.owner.value, environment: f.environment.value } });
        showSecretOnce(`Agent key for ${r.agent.slug}`, "Give this key to the agent (e.g. AGENTGUARD_KEY). It is shown only once.", r.api_key); render();
      } }]);
    };
    return [pageHead("Agents", "Each agent authenticates with its own key. Pausing blocks everything it tries until resumed.", can("admin") ? h("button", { class: "btn primary", onclick: create }, "Register agent") : null),
      panel(null, agents.length ? h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Agent", "Owner", "Status", "Last 24h", "Last seen", "Key", ""].map((c) => h("th", {}, c)))),
        h("tbody", {}, agents.map((a) => h("tr", {},
          h("td", {}, h("b", {}, a.name), h("div", { class: "mono faint" }, `${a.slug} · ${a.environment}`)), h("td", {}, a.owner || h("span", { class: "faint" }, "–")),
          h("td", {}, pill(a.status), a.paused_reason ? h("div", { class: "muted" }, a.paused_reason) : null),
          h("td", { class: "mono" }, Object.entries(a.last_24h).map(([k, v]) => h("div", {}, `${k.replace(/_/g, " ")}: ${v}`)), Object.keys(a.last_24h).length ? null : h("span", { class: "faint" }, "idle")),
          h("td", { class: "muted nowrap" }, ago(a.last_seen_at)), h("td", { class: "mono faint" }, a.key_prefix),
          h("td", { class: "nowrap" }, can("admin") && a.status !== "disabled" ? h("div", { class: "row" },
            a.status === "active" ? h("button", { class: "btn small danger", onclick: () => {
              const reason = h("input", { value: "manual pause" });
              modal(`Pause ${a.slug}?`, [h("p", { class: "muted" }, "Every action it attempts will be blocked until someone resumes it."), h("label", { class: "field" }, "Reason", reason)],
                [{ label: "Cancel" }, { label: "Pause agent", cls: "danger", run: act(`/v1/admin/agents/${a.id}/pause`, { reason: reason.value }, "Agent paused") }]);
            } }, "Pause") : h("button", { class: "btn small", onclick: act(`/v1/admin/agents/${a.id}/resume`, null, "Agent resumed") }, "Resume"),
            h("button", { class: "btn small", onclick: () => modal(`Rotate key for ${a.slug}?`, h("p", { class: "muted" }, "The current key stops working immediately."),
              [{ label: "Cancel" }, { label: "Rotate key", cls: "primary", run: async () => { const r = await api(`/v1/admin/agents/${a.id}/rotate-key`, { method: "POST" }); showSecretOnce(`New key for ${a.slug}`, "The previous key no longer works.", r.api_key); } }]) }, "Rotate key"),
            h("button", { class: "btn small danger", onclick: () => modal(`Disable ${a.slug} permanently?`, h("p", { class: "muted" }, "Its key stops working for good. History is kept. This cannot be undone."),
              [{ label: "Cancel" }, { label: "Disable", cls: "danger", run: act(`/v1/admin/agents/${a.id}/disable`, { reason: "disabled from dashboard" }, "Agent disabled") }]) }, "Disable")) : null)))))) : empty("No agents yet. Register one to get its key."))];
  }

  async function policiesView() {
    const [active, versions] = await Promise.all([api("/v1/admin/policies/active").catch(() => null), api("/v1/admin/policies")]);
    const editor = h("textarea", { class: "editor", spellcheck: "false", value: active ? active.source : "", disabled: !can("admin") });
    editor.addEventListener("keydown", (e) => { if (e.key === "Tab") { e.preventDefault(); const s = editor.selectionStart; editor.setRangeText("  ", s, editor.selectionEnd, "end"); } });
    const out = h("div", { class: "stack" });
    const comment = h("input", { class: "grow", placeholder: "What changed? (recorded with the version)" });
    const activate = h("input", { type: "checkbox", checked: true });
    const showValidation = (r) => {
      out.replaceChildren(
        r.valid ? h("div", { class: "notice ok" }, `Valid · ${r.summary.rules} rules, ${r.summary.rate_limits} rate limits, default ${r.summary.default} · actions: ${r.summary.actions.join(", ") || "none"}`)
          : h("div", { class: "notice bad" }, h("b", {}, "Not valid"), h("ul", {}, r.errors.map((e) => h("li", {}, e)))),
        ...(r.warnings || []).map((w) => h("div", { class: "notice warn" }, w)));
    };
    const validate = guard(async () => showValidation(await api("/v1/admin/policies/validate", { method: "POST", body: { source: editor.value } })));
    const save = guard(async () => {
      const v = await api("/v1/admin/policies/validate", { method: "POST", body: { source: editor.value } });
      if (!v.valid) return showValidation(v);
      const r = await api("/v1/admin/policies", { method: "POST", body: { source: editor.value, comment: comment.value, activate: activate.checked } });
      toast(`Saved version ${r.version}${r.active ? " (active)" : ""}`); render();
    });
    const sim = { agent: h("input", { value: "support-bot", class: "w-140" }), action: h("select", {}, (active ? active.actions : []).map((a) => h("option", { value: a }, a))),
      params: h("textarea", { rows: 3, value: '{"customer_id": "cus_alice", "amount": 120}' }), out: h("div", {}) };
    const simulate = guard(async () => {
      let params; try { params = JSON.parse(sim.params.value || "{}"); } catch { return toast("Params must be valid JSON"); }
      const r = await api("/v1/admin/policies/simulate", { method: "POST", body: { agent: sim.agent.value.trim(), action: sim.action.value, params } });
      sim.out.replaceChildren(r.valid ? h("div", { class: "row" }, pill(r.decision), h("span", { class: "mono" }, r.rule_id || "default"), h("span", { class: "muted" }, r.reason),
        r.approvals ? h("span", { class: "muted" }, `· needs ${r.approvals.min} of ${r.approvals.roles.join("/")}`) : null) : h("div", { class: "notice bad" }, r.errors.join("; ")));
    });
    const showDiff = guard(async (from, to) => {
      const d = await api(`/v1/admin/policies/diff?from_version=${from}&to_version=${to}`);
      modal(`Changes from v${from} to v${to}`, h("pre", { class: "diff" }, d.diff ? d.diff.split("\n").map((l) =>
        h("div", { class: l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : l.startsWith("@@") ? "hunk" : "" }, l || " ")) : "No differences."));
    });
    return [pageHead("Policies", "Policy as code. Saving creates a new immutable version; activate any version to roll back."),
      h("div", { class: "grid-main-side" },
        h("div", { class: "stack" },
          panel(active ? `Editing from v${active.version}` : "No active policy", h("div", { class: "body stack" }, editor, out,
            can("admin") ? h("div", { class: "row" }, comment, h("label", { class: "check" }, activate, "Activate"), h("button", { class: "btn", onclick: validate }, "Validate"), h("button", { class: "btn primary", onclick: save }, "Save version"))
              : h("span", { class: "muted" }, "Only admins can change policy."))),
          panel("Simulator", h("div", { class: "body stack" }, h("p", { class: "muted m0" }, "Dry-run a request against the active policy. Nothing executes."),
            h("div", { class: "row" }, sim.agent, sim.action, h("button", { class: "btn primary", onclick: simulate }, "Evaluate")), sim.params, sim.out))),
        panel("Versions", h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, versions.map((v) => h("tr", {},
          h("td", {}, h("b", {}, `v${v.version}`), " ", v.active ? pill("active") : null, h("div", { class: "muted" }, v.comment || h("span", { class: "faint" }, "no comment")),
            h("div", { class: "faint" }, `${v.created_by} · ${ago(v.created_at)}`)),
          h("td", { class: "nowrap right" },
            active && v.version !== active.version ? h("button", { class: "btn small", onclick: () => showDiff(v.version, active.version) }, "Diff") : null, " ",
            can("admin") && !v.active ? h("button", { class: "btn small", onclick: guard(async () => { await api(`/v1/admin/policies/${v.version}/activate`, { method: "POST" }); toast(`v${v.version} is now active`); render(); }) }, "Activate") : null)))))))),
    ];
  }

  async function secretsView() {
    const secrets = await api("/v1/admin/secrets");
    const name = h("input", { placeholder: "stripe_key", pattern: "[a-z][a-z0-9_]*" });
    const value = h("input", { type: "password", placeholder: "value", autocomplete: "off", class: "grow" });
    const save = guard(async () => { await api(`/v1/admin/secrets/${encodeURIComponent(name.value.trim())}`, { method: "PUT", body: { value: value.value } }); toast("Secret saved"); render(); });
    return [pageHead("Secrets", "Credentials the gateway uses on agents' behalf. Encrypted at rest and never shown again after saving; agents never see them."),
      panel("Add or replace a secret", h("div", { class: "body row" }, name, value, h("button", { class: "btn primary", onclick: save }, "Save"))),
      h("div", { class: "spacer" }),
      panel(null, secrets.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Name", "Used by", "Updated", ""].map((c) => h("th", {}, c)))),
        h("tbody", {}, secrets.map((s) => h("tr", {}, h("td", { class: "mono" }, s.name), h("td", {}, s.used_by.length ? s.used_by.join(", ") : h("span", { class: "faint" }, "not referenced by the active policy")),
          h("td", { class: "muted" }, `${ago(s.updated_at)} by ${s.created_by}`),
          h("td", { class: "right" }, h("button", { class: "btn small danger", onclick: () => modal(`Delete ${s.name}?`, h("p", { class: "muted" }, "Connectors that use it will fail until it is set again."),
            [{ label: "Cancel" }, { label: "Delete", cls: "danger", run: async () => { await api(`/v1/admin/secrets/${encodeURIComponent(s.name)}`, { method: "DELETE" }); toast("Deleted"); render(); } }]) }, "Delete"))))))) : empty("No secrets stored."))];
  }

  async function integrationsView() {
    const [{ channels, events }, deliveries] = await Promise.all([api("/v1/admin/channels"), api("/v1/admin/deliveries?limit=50")]);
    const eventChecks = (selected) => events.map((e) => { const c = h("input", { type: "checkbox", checked: selected.includes(e), value: e }); return { e, c, el: h("label", { class: "check" }, c, e) }; });
    const add = (kind) => {
      const name = h("input", { placeholder: kind === "slack" ? "#ops-approvals" : "Ops webhook" });
      const fields = kind === "webhook" ? { url: h("input", { placeholder: "https://example.com/agentguard" }) }
        : { channel: h("input", { placeholder: "C0123456789 or #approvals" }), bot_token: h("input", { type: "password", placeholder: "xoxb-…" }), signing_secret: h("input", { type: "password" }) };
      const checks = eventChecks(events);
      modal(kind === "slack" ? "Add Slack channel" : "Add webhook", [
        h("label", { class: "field" }, "Name", name),
        ...Object.entries(fields).map(([k, el]) => h("label", { class: "field" }, k.replace(/_/g, " "), el)),
        kind === "slack" ? h("p", { class: "muted" }, "Slack app scopes: chat:write, users:read, users:read.email. After saving, set the app's Interactivity Request URL to the URL shown on this page.") : null,
        h("div", { class: "field" }, "Events", h("div", { class: "row" }, checks.map((x) => x.el)))],
      [{ label: "Cancel" }, { label: "Save", cls: "primary", run: async () => {
        const config = Object.fromEntries(Object.entries(fields).map(([k, el]) => [k, el.value.trim()]));
        const r = await api("/v1/admin/channels", { method: "POST", body: { kind, name: name.value, config, events: checks.filter((x) => x.c.checked).map((x) => x.e) } });
        if (r.signing_secret) showSecretOnce("Webhook signing secret", "Verify the X-AgentGuard-Signature header with this secret. It is shown only once.", r.signing_secret);
        else if (r.interactions_url) showSecretOnce("Slack Interactivity Request URL", "Paste this into your Slack app under Interactivity & Shortcuts.", r.interactions_url);
        render();
      } }]);
    };
    const patch = (id, body) => guard(async () => { await api(`/v1/admin/channels/${id}`, { method: "PATCH", body }); render(); });
    return [pageHead("Integrations", "Where AgentGuard sends approval requests and alerts.", h("div", { class: "row" },
      h("button", { class: "btn", onclick: () => add("webhook") }, "Add webhook"), h("button", { class: "btn primary", onclick: () => add("slack") }, "Add Slack channel"))),
      panel("Channels", channels.length ? h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, channels.map((c) => h("tr", {},
        h("td", {}, h("b", {}, c.name), " ", pill(c.kind, "role"), h("div", { class: "mono faint" }, c.config.url || c.config.channel),
          c.interactions_url ? h("div", { class: "faint" }, "Interactivity URL: ", h("span", { class: "mono" }, c.interactions_url)) : null),
        h("td", { class: "muted" }, c.events.join(", ")), h("td", {}, pill(c.enabled ? "active" : "disabled")),
        h("td", { class: "nowrap right" },
          h("button", { class: "btn small", onclick: guard(async () => { const r = await api(`/v1/admin/channels/${c.id}/test`, { method: "POST" }); toast(r.ok ? "Test sent" : `Test failed: ${r.error}`); }) }, "Send test"), " ",
          h("button", { class: "btn small", onclick: patch(c.id, { enabled: !c.enabled }) }, c.enabled ? "Disable" : "Enable"), " ",
          h("button", { class: "btn small danger", onclick: guard(async () => { await api(`/v1/admin/channels/${c.id}`, { method: "DELETE" }); render(); }) }, "Delete"))))))) : empty("No channels. Add Slack to approve from Slack, or a webhook to feed your own systems.")),
      h("div", { class: "spacer" }),
      panel("Recent deliveries", deliveries.length ? h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["When", "Event", "Status", "Attempts", "Error"].map((c) => h("th", {}, c)))),
        h("tbody", {}, deliveries.map((d) => h("tr", {}, h("td", { class: "muted nowrap" }, ago(d.created_at)), h("td", { class: "mono" }, d.event_type), h("td", {}, pill(d.status)),
          h("td", {}, d.attempts), h("td", { class: "muted" }, d.last_error || "")))))) : empty("Nothing sent yet."))];
  }

  async function teamView() {
    const [members, invites, tokens] = await Promise.all([api("/v1/admin/members"), can("admin") ? api("/v1/admin/invitations") : [], can("admin") ? api("/v1/admin/tokens") : []]);
    const grantable = Object.keys(ROLE_RANK).filter((r) => ROLE_RANK[r] <= ROLE_RANK[S.me.role]);
    const invite = () => {
      const email = h("input", { type: "email" });
      const role = h("select", {}, grantable.map((r) => h("option", { value: r, selected: r === "approver" }, r)));
      modal("Invite a teammate", [h("label", { class: "field" }, "Email", email), h("label", { class: "field" }, "Role", role),
        h("p", { class: "muted" }, "viewer: read-only · approver: decides on actions · admin: manages agents, policies, secrets · owner: everything")],
      [{ label: "Cancel" }, { label: "Create invitation", cls: "primary", run: async () => {
        const r = await api("/v1/admin/invitations", { method: "POST", body: { email: email.value, role: role.value } });
        showSecretOnce(`Invitation for ${r.email}`, "Send this link to them. It works once and expires; it is shown only now.", r.accept_url); render();
      } }]);
    };
    const newToken = () => {
      const name = h("input", { placeholder: "terraform-ci" });
      const role = h("select", {}, grantable.map((r) => h("option", { value: r }, r)));
      modal("Create API token", [h("label", { class: "field" }, "Name", name), h("label", { class: "field" }, "Role", role),
        h("p", { class: "muted" }, "For automation (CI, scripts). Tokens can't approve actions; only people can.")],
      [{ label: "Cancel" }, { label: "Create", cls: "primary", run: async () => {
        const r = await api("/v1/admin/tokens", { method: "POST", body: { name: name.value, role: role.value } });
        showSecretOnce(`API token ${r.name}`, "Use as Authorization: Bearer <token>. Shown only once.", r.token); render();
      } }]);
    };
    return [pageHead("Team", "People and automation with access to this organization.", can("admin") ? h("div", { class: "row" }, h("button", { class: "btn", onclick: newToken }, "New API token"), h("button", { class: "btn primary", onclick: invite }, "Invite")) : null),
      panel("Members", h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, members.map((m) => h("tr", {},
        h("td", {}, h("b", {}, m.name || m.email), h("div", { class: "faint" }, m.email)), h("td", { class: "muted" }, `last sign-in ${ago(m.last_login_at)}`),
        h("td", {}, m.slack_linked ? pill("slack linked", "role") : null),
        h("td", { class: "nowrap right" }, can("admin") && (m.role !== "owner" || can("owner")) ? h("div", { class: "row end" },
          h("select", { onchange: guard(async (e) => { await api(`/v1/admin/members/${m.id}`, { method: "PATCH", body: { role: e.target.value } }); toast("Role updated"); render(); }) },
            grantable.map((r) => h("option", { value: r, selected: r === m.role }, r))),
          h("button", { class: "btn small danger", onclick: () => modal(`Remove ${m.email}?`, h("p", { class: "muted" }, "They lose access immediately."),
            [{ label: "Cancel" }, { label: "Remove", cls: "danger", run: async () => { await api(`/v1/admin/members/${m.id}`, { method: "DELETE" }); render(); } }]) }, "Remove")) : pill(m.role, "role")))))))),
      can("admin") && invites.length ? [h("div", { class: "spacer" }), panel("Pending invitations", h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, invites.map((i) => h("tr", {},
        h("td", {}, i.email), h("td", {}, pill(i.role, "role")), h("td", { class: "muted" }, `invited by ${i.invited_by} · expires ${when(i.expires_at)}`),
        h("td", { class: "right" }, h("button", { class: "btn small", onclick: guard(async () => { await api(`/v1/admin/invitations/${i.id}`, { method: "DELETE" }); render(); }) }, "Revoke"))))))))] : null,
      can("admin") ? [h("div", { class: "spacer" }), panel("API tokens", tokens.length ? h("div", { class: "table-wrap" }, h("table", {}, h("tbody", {}, tokens.map((t) => h("tr", {},
        h("td", {}, h("b", {}, t.name), h("div", { class: "mono faint" }, t.prefix)), h("td", {}, pill(t.role, "role")),
        h("td", { class: "muted" }, `by ${t.created_by} · used ${ago(t.last_used_at)}`),
        h("td", { class: "right" }, t.revoked ? pill("revoked", "disabled") : h("button", { class: "btn small danger", onclick: guard(async () => { await api(`/v1/admin/tokens/${t.id}`, { method: "DELETE" }); toast("Token revoked"); render(); }) }, "Revoke"))))))) : empty("No API tokens."))] : null];
  }

  async function auditView() {
    const events = await api("/v1/admin/audit?limit=300");
    const result = h("div", { class: "muted" }, "Each event commits to the hash of the one before it. Editing, deleting or reordering any past event breaks verification.");
    const verify = guard(async () => {
      const v = await api("/v1/admin/audit/verify");
      result.replaceChildren(v.valid ? h("div", { class: "notice ok" }, `Chain intact · ${v.events} events · head ${v.head.slice(0, 16)}…`)
        : h("div", { class: "notice bad" }, `Chain broken at event #${v.broken_at}: ${v.problem}`));
    });
    const exportAll = guard(async () => {
      const res = await fetch("/v1/admin/audit/export", { headers: { Authorization: `Bearer ${S.token}` } });
      if (!res.ok) throw new Error(`Export failed (HTTP ${res.status})`);
      const url = URL.createObjectURL(await res.blob());
      const a = h("a", { href: url, download: `agentguard-audit-${S.me.org.slug}.ndjson` }); document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    });
    return [pageHead("Audit log", "Every decision, approval and configuration change, in order.", h("div", { class: "row" },
      can("admin") ? h("button", { class: "btn", onclick: exportAll }, "Export NDJSON") : null, h("button", { class: "btn primary", onclick: verify }, "Verify chain"))),
      panel(null, h("div", { class: "body" }, result)), h("div", { class: "spacer" }),
      panel(null, h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["#", "When", "Actor", "Event", "Data", "Hash"].map((c) => h("th", {}, c)))),
        h("tbody", {}, events.map((e) => h("tr", e.request_id ? { class: "click", onclick: () => go(`actions/${e.request_id}`) } : {},
          h("td", { class: "mono" }, e.seq), h("td", { class: "muted nowrap", title: when(e.ts) }, ago(e.ts)), h("td", { class: "nowrap" }, e.actor),
          h("td", { class: "mono nowrap" }, e.event_type), h("td", { class: "mono params", title: compact(e.data) }, compact(e.data)), h("td", { class: "mono faint" }, e.hash.slice(0, 10) + "…")))))))];
  }

  // ----------------------------------------------------------------- render
  const VIEWS = { overview: overviewView, approvals: approvalsView, actions: actionsView, agents: agentsView, policies: policiesView,
    secrets: secretsView, integrations: integrationsView, team: teamView, audit: auditView };
  const LIVE = new Set(["overview", "approvals", "actions"]);  // auto-refreshing views
  let renderSeq = 0;

  async function render(opts = {}) {
    const root = document.getElementById("root");
    if (!S.token) { root.replaceChildren(authView()); return; }
    if (!S.me) { try { await loadMe(); } catch (e) { toast(e.message); return; } }
    const r = route();
    if (["login", "signup", "accept-invite"].includes(r.parts[0])) return go("overview");
    const name = r.parts[0];
    const view = name === "actions" && r.parts[1] ? () => actionDetailView(r.parts[1]) : VIEWS[name];
    if (!view) return go("overview");
    const seq = ++renderSeq;
    let content;
    try { content = await view(); } catch (e) { content = [pageHead("Something went wrong"), h("div", { class: "notice bad" }, e.message)]; }
    if (seq !== renderSeq) return;  // a newer render started meanwhile
    const scroll = window.scrollY;
    root.replaceChildren(shell(content));
    if (opts.keepScroll) window.scrollTo(0, scroll);
  }

  function startPolling() {
    clearInterval(S.timer);
    S.timer = setInterval(() => {
      if (!S.token || document.hidden || document.querySelector(".overlay")) return;
      const active = document.activeElement;
      if (active && ["INPUT", "TEXTAREA", "SELECT"].includes(active.tagName)) return;  // don't clobber typing
      const r = route();
      if (LIVE.has(r.parts[0])) render({ keepScroll: true });
    }, 5000);
  }

  (async () => {
    try { S.signupEnabled = (await api("/v1/auth/config")).signup_enabled; } catch {}
    await render();
    startPolling();
  })();
  document.addEventListener("visibilitychange", () => { if (!document.hidden && S.token) render({ keepScroll: true }); });
})();
