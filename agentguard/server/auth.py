"""Identity: users, organizations, roles, sessions, API tokens and invitations.

Roles (each includes the ones below it):
  owner     everything, including managing owners
  admin     agents, policies, secrets, integrations, members (except owners), tokens
  approver  decide on pending actions
  viewer    read-only

Approving actions is reserved for human users; API tokens cannot approve,
so automation can never rubber-stamp an agent's request.
"""
from __future__ import annotations

import datetime as dt
import re
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select

from agentguard.server import audit
from agentguard.server.config import ROLES
from agentguard.server.db import (
    GENESIS,
    ApiToken,
    Invitation,
    Membership,
    Organization,
    User,
    UserSession,
    iso,
    utcnow,
)
from agentguard.server.security import (
    DUMMY_PASSWORD_HASH,
    constant_time_equal,
    digest,
    hash_password,
    new_opaque,
    new_prefixed,
    parse_prefix,
    password_problems,
    token_kind,
    verify_password,
)
from agentguard.server.settings import Settings
from agentguard.server.store import ApiError, Store, new_id

ROLE_RANK = {"viewer": 0, "approver": 1, "admin": 2, "owner": 3}
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}$")


@dataclass(frozen=True)
class Principal:
    kind: str  # user | token
    org_id: str
    role: str
    label: str  # email or token name
    user_id: str | None = None
    token_id: str | None = None
    session_hash: str | None = None

    @property
    def actor(self) -> str:
        return f"{self.kind}:{self.label}"

    def has_role(self, role: str) -> bool:
        return ROLE_RANK[self.role] >= ROLE_RANK[role]

    def require(self, role: str) -> None:
        if not self.has_role(role):
            raise ApiError(403, f"this requires the {role} role (you are {self.role})")


def normalize_email(email: str) -> str:
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise ApiError(422, "invalid email address")
    return email


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:48]
    return slug or "org"


class LoginThrottle:
    """At most `limit` failed logins per email and per IP within `window` seconds."""

    def __init__(self, limit: int = 5, window: float = 900.0):
        self.limit, self.window = limit, window
        self._fails: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque:
        q = self._fails[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def check(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            if any(len(self._prune(k, now)) >= self.limit for k in keys):
                raise ApiError(429, "too many failed sign-in attempts; try again later")

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for k in keys:
                self._fails[k].append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._fails.pop(key, None)


class IdentityService:
    def __init__(self, store: Store, settings: Settings, on_org_created: Callable[[str, str], None] | None = None):
        self.store = store
        self.settings = settings
        self.throttle = LoginThrottle()
        self._on_org_created = on_org_created

    # --------------------------------------------------------- orgs & users

    def create_org_with_owner(self, org_name: str, email: str, password: str, name: str = "") -> tuple[dict, dict]:
        email = normalize_email(email)
        problems = password_problems(password)
        if problems:
            raise ApiError(422, "; ".join(problems))
        if not org_name.strip():
            raise ApiError(422, "organization name is required")
        pw_hash = hash_password(password)
        with self.store.tx_global() as s:
            if s.execute(select(User).where(User.email == email)).scalar_one_or_none():
                raise ApiError(409, "an account with this email already exists; sign in and create the organization from there")
            org = self._new_org(s, org_name)
            user = User(id=new_id("usr"), email=email, name=name.strip(), password_hash=pw_hash)
            s.add(user)
            s.flush()
            s.add(Membership(org_id=org.id, user_id=user.id, role="owner"))
            audit.append(s, org, actor=f"user:{email}", event_type="org.created", data={"name": org.name})
            org_d, user_d = self._org_dict(org), self._user_dict(user)
        if self._on_org_created:
            self._on_org_created(org_d["id"], f"user:{email}")
        return org_d, user_d

    def create_additional_org(self, principal: Principal, org_name: str) -> dict:
        if principal.kind != "user":
            raise ApiError(403, "only users can create organizations")
        with self.store.tx_global() as s:
            org = self._new_org(s, org_name)
            s.flush()
            s.add(Membership(org_id=org.id, user_id=principal.user_id, role="owner"))
            audit.append(s, org, actor=principal.actor, event_type="org.created", data={"name": org.name})
            org_d = self._org_dict(org)
        if self._on_org_created:
            self._on_org_created(org_d["id"], principal.actor)
        return org_d

    def _new_org(self, s, org_name: str) -> Organization:
        base = slugify(org_name)
        slug, n = base, 1
        while s.execute(select(Organization.id).where(Organization.slug == slug)).first():
            n += 1
            slug = f"{base}-{n}"
        org = Organization(id=new_id("org"), name=org_name.strip()[:200], slug=slug, audit_seq=0, audit_head=GENESIS)
        s.add(org)
        return org

    # -------------------------------------------------------------- sessions

    def login(self, email: str, password: str, ip: str = "", user_agent: str = "", org_id: str | None = None) -> dict:
        email = email.strip().lower()
        self.throttle.check(f"email:{email}", f"ip:{ip}")
        with self.store.read() as s:
            user = s.execute(select(User).where(User.email == email)).scalar_one_or_none()
            memberships = s.execute(select(Membership).where(Membership.user_id == user.id)).scalars().all() if user else []
        ok = verify_password(password, user.password_hash if user else DUMMY_PASSWORD_HASH)
        if not user or not ok or not user.is_active:
            self.throttle.fail(f"email:{email}", f"ip:{ip}")
            raise ApiError(401, "incorrect email or password")
        if not memberships:
            raise ApiError(403, "this account does not belong to any organization")
        self.throttle.reset(f"email:{email}")
        target = org_id if org_id and any(m.org_id == org_id for m in memberships) else memberships[0].org_id
        token, token_hash = new_opaque("ags")
        with self.store.tx(target) as (s, org):
            s.add(UserSession(token_hash=token_hash, user_id=user.id, org_id=target, ip=ip[:64], user_agent=user_agent[:300],
                              expires_at=utcnow() + dt.timedelta(hours=self.settings.session_ttl_hours)))
            u = s.get(User, user.id)
            u.last_login_at = utcnow()
            audit.append(s, org, actor=f"user:{email}", event_type="user.signed_in", data={"ip": ip})
        return {"token": token, "expires_in": self.settings.session_ttl_hours * 3600}

    def logout(self, principal: Principal) -> None:
        if principal.session_hash:
            with self.store.tx_global() as s:
                sess = s.get(UserSession, principal.session_hash)
                if sess:
                    s.delete(sess)

    def switch_org(self, principal: Principal, org_id: str) -> None:
        if not principal.session_hash:
            raise ApiError(400, "only dashboard sessions can switch organizations")
        with self.store.tx_global() as s:
            if not s.get(Membership, (org_id, principal.user_id)):
                raise ApiError(404, "organization not found")
            sess = s.get(UserSession, principal.session_hash)
            sess.org_id = org_id

    def change_password(self, principal: Principal, current: str, new: str) -> None:
        if principal.kind != "user":
            raise ApiError(403, "only users have passwords")
        problems = password_problems(new)
        if problems:
            raise ApiError(422, "; ".join(problems))
        with self.store.tx(principal.org_id) as (s, org):
            user = s.get(User, principal.user_id)
            if not verify_password(current, user.password_hash):
                raise ApiError(403, "current password is incorrect")
            user.password_hash = hash_password(new)
            # Sign out every other session.
            for sess in s.execute(select(UserSession).where(UserSession.user_id == user.id)).scalars():
                if sess.token_hash != principal.session_hash:
                    s.delete(sess)
            audit.append(s, org, actor=principal.actor, event_type="user.password_changed")

    def authenticate(self, token: str) -> Principal | None:
        kind = token_kind(token)
        now = utcnow()
        if kind == "ags":
            with self.store.read() as s:
                sess = s.get(UserSession, digest(token))
                if sess is None or sess.expires_at < now:
                    return None
                user = s.get(User, sess.user_id)
                membership = s.get(Membership, (sess.org_id, sess.user_id))
                if user is None or not user.is_active or membership is None:
                    return None
                return Principal("user", sess.org_id, membership.role, user.email, user_id=user.id, session_hash=sess.token_hash)
        if kind == "agt":
            prefix = parse_prefix(token)
            if not prefix:
                return None
            token_hash = digest(token)
            with self.store.read() as s:
                rows = s.execute(select(ApiToken).where(ApiToken.prefix == prefix, ApiToken.revoked_at.is_(None))).scalars().all()
                match = next((t for t in rows if constant_time_equal(t.token_hash, token_hash)), None)
            if match is None:
                return None
            if match.last_used_at is None or (now - match.last_used_at).total_seconds() > 300:
                with self.store.tx_global() as s:
                    t = s.get(ApiToken, match.id)
                    t.last_used_at = now
            return Principal("token", match.org_id, match.role, match.name, token_id=match.id)
        return None

    def me(self, principal: Principal) -> dict:
        with self.store.read() as s:
            orgs = s.execute(
                select(Organization, Membership.role).join(Membership, Membership.org_id == Organization.id)
                .where(Membership.user_id == principal.user_id).order_by(Organization.name)
            ).all() if principal.user_id else []
            user = s.get(User, principal.user_id) if principal.user_id else None
            current = s.get(Organization, principal.org_id)
        return {
            "kind": principal.kind,
            "user": self._user_dict(user) if user else None,
            "token": {"id": principal.token_id, "name": principal.label} if principal.kind == "token" else None,
            "org": self._org_dict(current),
            "role": principal.role,
            "organizations": [{**self._org_dict(o), "role": r} for o, r in orgs],
        }

    # --------------------------------------------------------------- members

    def list_members(self, principal: Principal) -> list[dict]:
        with self.store.read() as s:
            rows = s.execute(
                select(User, Membership).join(Membership, Membership.user_id == User.id)
                .where(Membership.org_id == principal.org_id).order_by(User.email)
            ).all()
        return [{**self._user_dict(u), "role": m.role, "slack_linked": bool(m.slack_user_id), "joined_at": iso(m.created_at)} for u, m in rows]

    def _check_role_grant(self, principal: Principal, role: str) -> None:
        if role not in ROLES:
            raise ApiError(422, f"role must be one of {list(ROLES)}")
        principal.require("admin")
        if ROLE_RANK[role] > ROLE_RANK[principal.role]:
            raise ApiError(403, f"you cannot grant a role above your own ({principal.role})")

    def update_member_role(self, principal: Principal, user_id: str, role: str) -> dict:
        self._check_role_grant(principal, role)
        with self.store.tx(principal.org_id) as (s, org):
            m = s.get(Membership, (principal.org_id, user_id))
            if m is None:
                raise ApiError(404, "member not found")
            if m.role == "owner" and not principal.has_role("owner"):
                raise ApiError(403, "only owners can change an owner's role")
            if m.role == "owner" and role != "owner" and self._owner_count(s, principal.org_id) <= 1:
                raise ApiError(409, "an organization must keep at least one owner")
            before, m.role = m.role, role
            user = s.get(User, user_id)
            audit.append(s, org, actor=principal.actor, event_type="member.role_changed", data={"user": user.email, "from": before, "to": role})
        return {"user_id": user_id, "role": role}

    def remove_member(self, principal: Principal, user_id: str) -> None:
        principal.require("admin")
        with self.store.tx(principal.org_id) as (s, org):
            m = s.get(Membership, (principal.org_id, user_id))
            if m is None:
                raise ApiError(404, "member not found")
            if m.role == "owner":
                if not principal.has_role("owner"):
                    raise ApiError(403, "only owners can remove an owner")
                if self._owner_count(s, principal.org_id) <= 1:
                    raise ApiError(409, "an organization must keep at least one owner")
            user = s.get(User, user_id)
            s.delete(m)
            for sess in s.execute(select(UserSession).where(UserSession.user_id == user_id, UserSession.org_id == principal.org_id)).scalars():
                s.delete(sess)
            audit.append(s, org, actor=principal.actor, event_type="member.removed", data={"user": user.email, "role": m.role})

    def _owner_count(self, s, org_id: str) -> int:
        return s.execute(select(func.count()).select_from(Membership).where(Membership.org_id == org_id, Membership.role == "owner")).scalar_one()

    # ----------------------------------------------------------- invitations

    def create_invitation(self, principal: Principal, email: str, role: str) -> dict:
        email = normalize_email(email)
        self._check_role_grant(principal, role)
        token, token_hash = new_opaque("agi")
        with self.store.tx(principal.org_id) as (s, org):
            existing = s.execute(select(User).where(User.email == email)).scalar_one_or_none()
            if existing and s.get(Membership, (principal.org_id, existing.id)):
                raise ApiError(409, f"{email} is already a member")
            inv = Invitation(id=new_id("inv"), org_id=org.id, email=email, role=role, token_hash=token_hash, invited_by=principal.label,
                             expires_at=utcnow() + dt.timedelta(hours=self.settings.invitation_ttl_hours))
            s.add(inv)
            audit.append(s, org, actor=principal.actor, event_type="member.invited", data={"email": email, "role": role})
            out = self._invitation_dict(inv)
        out["accept_url"] = f"{self.settings.public_url}/#/accept-invite?token={token}"
        out["token"] = token
        return out

    def list_invitations(self, principal: Principal) -> list[dict]:
        with self.store.read() as s:
            rows = s.execute(select(Invitation).where(Invitation.org_id == principal.org_id, Invitation.accepted_at.is_(None),
                                                      Invitation.revoked_at.is_(None)).order_by(Invitation.created_at.desc())).scalars().all()
        return [self._invitation_dict(i) for i in rows]

    def revoke_invitation(self, principal: Principal, invitation_id: str) -> None:
        principal.require("admin")
        with self.store.tx(principal.org_id) as (s, org):
            inv = s.get(Invitation, invitation_id)
            if inv is None or inv.org_id != org.id:
                raise ApiError(404, "invitation not found")
            inv.revoked_at = utcnow()
            audit.append(s, org, actor=principal.actor, event_type="member.invitation_revoked", data={"email": inv.email})

    def accept_invitation(self, token: str, password: str, name: str = "", ip: str = "", user_agent: str = "") -> dict:
        with self.store.read() as s:
            inv = s.execute(select(Invitation).where(Invitation.token_hash == digest(token))).scalar_one_or_none()
            if inv is None or inv.accepted_at or inv.revoked_at or inv.expires_at < utcnow():
                raise ApiError(404, "this invitation is invalid or has expired")
            user = s.execute(select(User).where(User.email == inv.email)).scalar_one_or_none()
            org_id, email, role = inv.org_id, inv.email, inv.role
        if user is not None:
            # Existing account: prove ownership with the current password.
            if not verify_password(password, user.password_hash):
                raise ApiError(403, "an account with this email exists; enter its current password to accept")
            pw_hash = None
        else:
            problems = password_problems(password)
            if problems:
                raise ApiError(422, "; ".join(problems))
            pw_hash = hash_password(password)
        with self.store.tx(org_id) as (s, org):
            inv = s.execute(select(Invitation).where(Invitation.token_hash == digest(token))).scalar_one()
            if inv.accepted_at:
                raise ApiError(409, "this invitation was already accepted")
            if user is None:
                user = User(id=new_id("usr"), email=email, name=name.strip(), password_hash=pw_hash)
                s.add(user)
                s.flush()
            if not s.get(Membership, (org_id, user.id)):
                s.add(Membership(org_id=org_id, user_id=user.id, role=role))
            inv.accepted_at = utcnow()
            audit.append(s, org, actor=f"user:{email}", event_type="member.joined", data={"role": role})
        return self.login(email, password, ip=ip, user_agent=user_agent, org_id=org_id)

    # ------------------------------------------------------------ API tokens

    def create_api_token(self, principal: Principal, name: str, role: str) -> dict:
        self._check_role_grant(principal, role)
        if not name.strip():
            raise ApiError(422, "token name is required")
        token, prefix, token_hash = new_prefixed("agt")
        with self.store.tx(principal.org_id) as (s, org):
            t = ApiToken(id=new_id("tok"), org_id=org.id, name=name.strip()[:200], prefix=prefix, token_hash=token_hash, role=role,
                         created_by=principal.label)
            s.add(t)
            audit.append(s, org, actor=principal.actor, event_type="api_token.created", data={"name": t.name, "role": role})
            out = self._token_dict(t)
        return {**out, "token": token}

    def list_api_tokens(self, principal: Principal) -> list[dict]:
        with self.store.read() as s:
            rows = s.execute(select(ApiToken).where(ApiToken.org_id == principal.org_id).order_by(ApiToken.created_at.desc())).scalars().all()
        return [self._token_dict(t) for t in rows]

    def revoke_api_token(self, principal: Principal, token_id: str) -> None:
        principal.require("admin")
        with self.store.tx(principal.org_id) as (s, org):
            t = s.get(ApiToken, token_id)
            if t is None or t.org_id != org.id:
                raise ApiError(404, "token not found")
            t.revoked_at = t.revoked_at or utcnow()
            audit.append(s, org, actor=principal.actor, event_type="api_token.revoked", data={"name": t.name})

    # ------------------------------------------------------------ serializers

    @staticmethod
    def _user_dict(u: User) -> dict[str, Any]:
        return {"id": u.id, "email": u.email, "name": u.name, "created_at": iso(u.created_at), "last_login_at": iso(u.last_login_at)}

    @staticmethod
    def _org_dict(o: Organization) -> dict[str, Any]:
        return {"id": o.id, "name": o.name, "slug": o.slug, "created_at": iso(o.created_at)}

    @staticmethod
    def _invitation_dict(i: Invitation) -> dict[str, Any]:
        return {"id": i.id, "email": i.email, "role": i.role, "invited_by": i.invited_by, "created_at": iso(i.created_at), "expires_at": iso(i.expires_at)}

    @staticmethod
    def _token_dict(t: ApiToken) -> dict[str, Any]:
        return {"id": t.id, "name": t.name, "role": t.role, "prefix": f"agt_{t.prefix}_…", "created_by": t.created_by,
                "created_at": iso(t.created_at), "last_used_at": iso(t.last_used_at), "revoked": t.revoked_at is not None}
