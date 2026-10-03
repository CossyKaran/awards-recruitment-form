// ============================================================================
// Awards Recruitment Ltd - Email notifications (Vercel serverless function)
// Address: /api/notify
//
// Sends two kinds of email via Brevo:
//   - send_verification: right after someone applies, confirms the email is real
//   - stage_update: when an admin moves an applicant to a new stage
//
// Why Brevo, not a domain-verified provider: Brevo lets you verify a single
// sender EMAIL ADDRESS you personally control (no company domain or DNS
// access needed) and still deliver to real recipients immediately. A domain
// can be added later for better deliverability, but nothing here depends on it.
//
// Security design (unchanged regardless of provider):
//   - The destination email address is NEVER taken from the request. It is
//     always looked up server-side from the applicant's own database row,
//     using the Supabase service key. This endpoint can only ever email the
//     address already on file for that applicant - never an attacker-supplied one.
//   - stage_update requires a signed-in ADMIN (checked against admin_profiles,
//     the same rule the database itself enforces for changing a stage).
//   - send_verification is public (applying is anonymous), but is rate-limited
//     per applicant so it can't be used to spam one inbox repeatedly.
//   - BREVO_API_KEY and the Supabase service key are read from Vercel's
//     Environment Variables and are never present in any file a visitor can download.
// ============================================================================

const SUPABASE_URL = "https://phxtdnnmggpmmcyeadxk.supabase.co";
const ANON_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InBoeHRkbm5tZ2dwbW1jeWVhZHhrIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTAzOTYwODMsImV4cCI6MjEwNTk3MjA4M30.rXzUoW5ZPhTQzAAQ9HctpUGjPS0YS5Rn1oEG5vx01HU";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const BREVO_API_KEY = process.env.BREVO_API_KEY;
// The single sender email you verified in Brevo (any address you personally
// control - a Gmail address is fine). No company domain required.
const FROM_EMAIL = process.env.BREVO_FROM_EMAIL;
const FROM_NAME = process.env.BREVO_FROM_NAME || "Awards Recruitment Ltd";
// The public site, used to build links inside emails (no trailing slash)
const SITE_URL = process.env.SITE_URL || "https://awards-recruitment-form.vercel.app";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VERIFICATION_COOLDOWN_MS = 2 * 60 * 1000; // 2 minutes between resends

const STAGE_LABELS = {
  initiated: "Application Initiated",
  documents_verified: "Documents Verified",
  profile_submitted: "Profile Submitted",
  offer_secured: "Offer Secured",
  work_permit: "Work Permit Processing",
  visa_processing: "Visa Processing",
  medical: "Medical Examination",
  travel_clearance: "Travel Clearance",
  complete: "Complete"
};

function serviceHeaders(extra) {
  return Object.assign({ apikey: SERVICE_KEY, Authorization: "Bearer " + SERVICE_KEY, "Content-Type": "application/json" }, extra || {});
}
function sbAdmin(path, options) {
  const o = options || {};
  return fetch(SUPABASE_URL + path, Object.assign({}, o, { headers: serviceHeaders(o.headers) }));
}
async function readJson(r) {
  const text = await r.text();
  try { return text ? JSON.parse(text) : {}; } catch (e) { return { raw: text }; }
}

async function getApplicant(id) {
  const r = await sbAdmin("/rest/v1/applicants?id=eq." + id + "&select=*");
  const rows = await readJson(r);
  return Array.isArray(rows) && rows[0] ? rows[0] : null;
}

async function getCaller(req) {
  const token = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const r = await fetch(SUPABASE_URL + "/auth/v1/user", { headers: { apikey: ANON_KEY, Authorization: "Bearer " + token } });
  if (!r.ok) return null;
  const u = await r.json();
  return u && u.id ? u : null;
}
async function callerIsAdmin(req) {
  const caller = await getCaller(req);
  if (!caller) return false;
  const r = await sbAdmin("/rest/v1/admin_profiles?id=eq." + caller.id + "&select=role,is_active");
  const rows = await readJson(r);
  const p = Array.isArray(rows) ? rows[0] : null;
  return !!(p && p.is_active && p.role === "admin");
}

async function sendEmail(toEmail, toName, subject, html) {
  if (!BREVO_API_KEY) throw new Error("Email sending isn't finished setting up yet (BREVO_API_KEY is missing in Vercel).");
  if (!FROM_EMAIL) throw new Error("Email sending isn't finished setting up yet (BREVO_FROM_EMAIL is missing in Vercel).");

  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      sender: { name: FROM_NAME, email: FROM_EMAIL },
      to: [{ email: toEmail, name: toName || undefined }],
      subject,
      htmlContent: html
    })
  });
  const body = await readJson(r);
  if (!r.ok) throw new Error(body.message || ("Brevo request failed (" + r.status + ")"));
  return body;
}

function wrapEmail(title, bodyHtml) {
  return `<div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;padding:32px 24px;color:#22262F;">
    <div style="background:#1D2753;color:#fff;padding:18px 24px;border-radius:10px 10px 0 0;">
      <strong style="font-size:16px;">Awards Recruitment Ltd</strong><br>
      <span style="font-size:11px;color:#D3AF54;letter-spacing:.5px;">YOUR 7 STAR JOBS AGENCY</span>
    </div>
    <div style="border:1px solid #E4E1D8;border-top:none;padding:28px 24px;border-radius:0 0 10px 10px;">
      <h2 style="color:#1D2753;font-size:19px;margin:0 0 14px;">${title}</h2>
      ${bodyHtml}
    </div>
    <p style="font-size:11px;color:#9AA3B2;margin-top:18px;">Awards Recruitment Ltd &middot; Nairobi, Kenya</p>
  </div>`;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : (req.body || {});
    const action = body.action;
    const applicantId = String(body.applicant_id || "");
    if (!UUID.test(applicantId)) return res.status(400).json({ error: "Unknown application." });

    // ---- send_verification (public: applying itself is anonymous) --------
    if (action === "send_verification") {
      const a = await getApplicant(applicantId);
      if (!a) return res.status(404).json({ error: "Application not found." });
      if (a.email_verified) return res.status(200).json({ ok: true, already_verified: true });

      if (a.verification_sent_at) {
        const since = Date.now() - new Date(a.verification_sent_at).getTime();
        if (since < VERIFICATION_COOLDOWN_MS) {
          return res.status(429).json({ error: "A verification email was just sent — please check your inbox (and spam folder) before requesting another." });
        }
      }

      const link = `${SITE_URL}/verify.html?token=${a.verification_token}`;
      const firstName = (a.full_name || "").split(" ")[0] || "there";
      const html = wrapEmail("Confirm your email address", `
        <p>Hi ${firstName},</p>
        <p>Thanks for applying${a.position_applied_for ? " for <strong>" + a.position_applied_for + "</strong>" : ""}. Please confirm this is your email address so we can send you updates as your application moves forward.</p>
        <p style="text-align:center;margin:26px 0;">
          <a href="${link}" style="background:#1D2753;color:#fff;padding:12px 26px;border-radius:8px;text-decoration:none;font-weight:bold;display:inline-block;">Confirm my email</a>
        </p>
        <p style="font-size:12px;color:#6B7280;">Or paste this link into your browser: ${link}</p>
      `);

      try {
        await sendEmail(a.email, a.full_name, "Confirm your email — Awards Recruitment Ltd", html);
      } catch (e) {
        return res.status(502).json({ error: "Could not send the email: " + e.message });
      }

      await sbAdmin("/rest/v1/applicants?id=eq." + applicantId, {
        method: "PATCH", headers: { Prefer: "return=minimal" },
        body: JSON.stringify({ verification_sent_at: new Date().toISOString() })
      });

      return res.status(200).json({ ok: true });
    }

    // ---- stage_update (admin-only) ----------------------------------------
    if (action === "stage_update") {
      if (!(await callerIsAdmin(req))) return res.status(403).json({ error: "Only administrators can trigger this." });

      const stage = String(body.stage || "");
      if (!STAGE_LABELS[stage]) return res.status(400).json({ error: "Unknown stage." });

      const a = await getApplicant(applicantId);
      if (!a) return res.status(404).json({ error: "Application not found." });
      if (!a.email_verified) return res.status(200).json({ ok: true, skipped: "email_not_verified" });

      const link = `${SITE_URL}/track.html?ref=AR-${applicantId.slice(0, 8).toUpperCase()}&email=${encodeURIComponent(a.email)}`;
      const firstName = (a.full_name || "").split(" ")[0] || "there";
      const html = wrapEmail("Your application has moved forward", `
        <p>Hi ${firstName},</p>
        <p>Your application${a.position_applied_for ? " for <strong>" + a.position_applied_for + "</strong>" : ""} is now at:</p>
        <p style="font-size:18px;font-weight:bold;color:#1D2753;background:#FBF6E7;padding:14px 18px;border-radius:8px;text-align:center;">${STAGE_LABELS[stage]}</p>
        <p style="text-align:center;margin:22px 0;">
          <a href="${link}" style="background:#1D2753;color:#fff;padding:12px 26px;border-radius:8px;text-decoration:none;font-weight:bold;display:inline-block;">View my progress</a>
        </p>
      `);

      try {
        await sendEmail(a.email, a.full_name, `Update: ${STAGE_LABELS[stage]} — Awards Recruitment Ltd`, html);
      } catch (e) {
        return res.status(502).json({ error: "Could not send the email: " + e.message });
      }

      return res.status(200).json({ ok: true });
    }

    return res.status(400).json({ error: "Unknown action." });
  } catch (e) {
    return res.status(500).json({ error: e.message || "Something went wrong." });
  }
};
