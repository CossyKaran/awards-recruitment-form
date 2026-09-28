// ============================================================================
// Awards Recruitment Ltd - Team management service (Vercel serverless function)
// Address: /api/team
//
// Lets a signed-in ADMIN add team members, reset their passwords, change roles
// and switch access on or off. It uses Supabase's secret key, which is read
// from Vercel's Environment Variables and must NEVER be pasted into any page
// or file that visitors can download.
// ============================================================================
const crypto = require("crypto");

const SUPABASE_URL = "https://phxtdnnmggpmmcyeadxk.supabase.co";
// Public "anon" key (safe to show; the same one your pages already use)
const ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBoeHRkbm5tZ2dwbW1jeWVhZHhrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTAzOTYwODMsImV4cCI6MjEwNTk3MjA4M30.rXzUoW5ZPhTQzAAQ9HctpUGjPS0YS5Rn1oEG5vx01HU";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ROLES = ["admin", "team_member"];

function serviceHeaders(extra) {
  const h = Object.assign({ apikey: SERVICE_KEY, "Content-Type": "application/json" }, extra || {});
  if (SERVICE_KEY && SERVICE_KEY.startsWith("eyJ")) h.Authorization = "Bearer " + SERVICE_KEY;
  return h;
}

function sb(path, options) {
  const o = options || {};
  return fetch(SUPABASE_URL + path, Object.assign({}, o, { headers: serviceHeaders(o.headers) }));
}

async function readJson(r) {
  const text = await r.text();
  try { return text ? JSON.parse(text) : {}; } catch (e) { return { raw: text }; }
}

// Readable temporary password (no look-alike characters), 12 characters
function tempPassword() {
  const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
  const lower = "abcdefghijkmnopqrstuvwxyz";
  const digits = "23456789";
  const all = upper + lower + digits;
  const pick = set => set[crypto.randomInt(set.length)];
  const chars = [pick(upper), pick(lower), pick(digits), pick(digits)];
  while (chars.length < 12) chars.push(pick(all));
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    const t = chars[i]; chars[i] = chars[j]; chars[j] = t;
  }
  return chars.join("");
}

async function getCaller(req) {
  const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const r = await fetch(SUPABASE_URL + "/auth/v1/user", {
    headers: { apikey: ANON_KEY, Authorization: "Bearer " + token }
  });
  if (!r.ok) return null;
  const u = await r.json();
  return u && u.id ? u : null;
}

async function getProfile(id) {
  const r = await sb("/rest/v1/admin_profiles?id=eq." + id + "&select=id,role,is_active");
  const rows = await readJson(r);
  return Array.isArray(rows) ? rows[0] : null;
}

async function activeAdminCount() {
  const r = await sb("/rest/v1/admin_profiles?select=id&role=eq.admin&is_active=eq.true");
  const rows = await readJson(r);
  return Array.isArray(rows) ? rows.length : 0;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  if (!SERVICE_KEY) {
    return res.status(500).json({ error: "The team service isn't finished setting up yet (the SUPABASE_SERVICE_ROLE_KEY setting is missing in Vercel)." });
  }

  try {
    // 1. Who is asking? Must be a signed-in, active ADMIN.
    const caller = await getCaller(req);
    if (!caller) return res.status(401).json({ error: "Please sign in again." });
    const me = await getProfile(caller.id);
    if (!me || !me.is_active || me.role !== "admin") {
      return res.status(403).json({ error: "Only administrators can manage the team." });
    }

    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const action = body.action;

    // ---- list ----------------------------------------------------------
    if (action === "list") {
      const pr = await sb("/rest/v1/admin_profiles?select=id,display_name,role,is_active,created_at&order=created_at.asc");
      const profiles = await readJson(pr);
      if (!pr.ok || !Array.isArray(profiles)) throw new Error("Could not read the team list.");
      const members = await Promise.all(profiles.map(async p => {
        const ur = await sb("/auth/v1/admin/users/" + p.id);
        const u = ur.ok ? await readJson(ur) : {};
        return {
          id: p.id,
          display_name: p.display_name,
          role: p.role,
          is_active: p.is_active,
          email: u.email || "",
          last_sign_in_at: u.last_sign_in_at || null,
          must_change_password: !!(u.user_metadata && u.user_metadata.must_change_password)
        };
      }));
      return res.status(200).json({ members });
    }

    // ---- create --------------------------------------------------------
    if (action === "create") {
      const email = String(body.email || "").trim().toLowerCase();
      const name = String(body.display_name || "").trim();
      const role = body.role;
      if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Please enter a valid email address." });
      if (name.length < 2) return res.status(400).json({ error: "Please enter the person's full name." });
      if (!ROLES.includes(role)) return res.status(400).json({ error: "Please choose a role." });

      const password = tempPassword();
      const cr = await sb("/auth/v1/admin/users", {
        method: "POST",
        body: JSON.stringify({
          email, password, email_confirm: true,
          user_metadata: { display_name: name, must_change_password: true }
        })
      });
      const created = await readJson(cr);
      if (!cr.ok || !created.id) {
        return res.status(400).json({ error: created.msg || created.message || created.error_description || "Could not create the account (does it already exist?)." });
      }

      const ins = await sb("/rest/v1/admin_profiles", {
        method: "POST",
        headers: { Prefer: "resolution=merge-duplicates,return=minimal" },
        body: JSON.stringify({ id: created.id, display_name: name, role, is_active: true })
      });
      if (!ins.ok) {
        await sb("/auth/v1/admin/users/" + created.id, { method: "DELETE" }); // undo, so nothing is left half-made
        return res.status(500).json({ error: "The login was created but its access record could not be saved, so it was undone. Please try again." });
      }
      return res.status(200).json({ ok: true, email, temp_password: password });
    }

    // Everything below acts on an existing team member
    const id = String(body.user_id || "");
    if (!UUID.test(id)) return res.status(400).json({ error: "Unknown team member." });
    const target = await getProfile(id);
    if (!target) return res.status(404).json({ error: "Team member not found." });

    // ---- reset_password -------------------------------------------------
    if (action === "reset_password") {
      const ur = await sb("/auth/v1/admin/users/" + id);
      const u = ur.ok ? await readJson(ur) : {};
      const password = tempPassword();
      const pr = await sb("/auth/v1/admin/users/" + id, {
        method: "PUT",
        body: JSON.stringify({
          password,
          user_metadata: Object.assign({}, u.user_metadata || {}, { must_change_password: true })
        })
      });
      if (!pr.ok) return res.status(400).json({ error: "Could not reset the password." });
      return res.status(200).json({ ok: true, email: u.email || "", temp_password: password });
    }

    // ---- set_role ---------------------------------------------------------
    if (action === "set_role") {
      const role = body.role;
      if (!ROLES.includes(role)) return res.status(400).json({ error: "Please choose a role." });
      if (id === caller.id) return res.status(400).json({ error: "You can't change your own role." });
      if (target.role === "admin" && role !== "admin" && target.is_active && (await activeAdminCount()) <= 1) {
        return res.status(400).json({ error: "At least one active admin must remain." });
      }
      const r = await sb("/rest/v1/admin_profiles?id=eq." + id, {
        method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ role })
      });
      if (!r.ok) return res.status(500).json({ error: "Could not change the role." });
      return res.status(200).json({ ok: true });
    }

    // ---- set_active --------------------------------------------------------
    if (action === "set_active") {
      const active = body.is_active === true;
      if (id === caller.id) return res.status(400).json({ error: "You can't switch off your own access." });
      if (!active && target.role === "admin" && target.is_active && (await activeAdminCount()) <= 1) {
        return res.status(400).json({ error: "At least one active admin must remain." });
      }
      const r = await sb("/rest/v1/admin_profiles?id=eq." + id, {
        method: "PATCH", headers: { Prefer: "return=minimal" }, body: JSON.stringify({ is_active: active })
      });
      if (!r.ok) return res.status(500).json({ error: "Could not change access." });
      // Also block (or unblock) the login itself. Best effort: the access record above already stops data access.
      await sb("/auth/v1/admin/users/" + id, {
        method: "PUT", body: JSON.stringify({ ban_duration: active ? "none" : "876000h" })
      });
      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: "Unknown action." });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Something went wrong." });
  }
};

module.exports.tempPassword = tempPassword;
