import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import pg from "pg";
import path from "node:path";
import { fileURLToPath } from "node:url";

const { Pool } = pg;
const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false });
const ADMIN = String(process.env.ADMIN_EMAIL || "cristian.damandaman@deped.gov.ph").toLowerCase();
const SECRET = process.env.SESSION_SECRET;
const __dirname = path.dirname(fileURLToPath(import.meta.url));
if (!SECRET) throw new Error("SESSION_SECRET is required");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "10mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: true, legacyHeaders: false });

async function init() {
  const sql = await import("node:fs/promises");
  const migration = await sql.readFile(path.join(__dirname, "migrations/001_init.sql"), "utf8");
  await pool.query(migration);
  await pool.query("ALTER TABLE app_admins ADD COLUMN IF NOT EXISTS password_hash TEXT");
  await pool.query("ALTER TABLE tm_accounts ADD COLUMN IF NOT EXISTS password_hash TEXT");
  await pool.query("ALTER TABLE events ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true");
  if (process.env.ADMIN_PASSWORD) {
    const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
    await pool.query("UPDATE app_admins SET password_hash=$1 WHERE email=$2", [hash, ADMIN]);
  }
}
function tokenFor(email, role) { return jwt.sign({ email, role }, SECRET, { expiresIn: "12h", issuer: "division-athletic-meet" }); }
function setSession(res, email, role) {
  res.cookie("dam_session", tokenFor(email, role), { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", maxAge: 12 * 60 * 60 * 1000, path: "/" });
}
async function identify(req, res, next) {
  try {
    const token = req.cookies.dam_session;
    if (!token) return res.status(401).json({ error: "Please sign in." });
    req.user = jwt.verify(token, SECRET, { issuer: "division-athletic-meet" });
    next();
  } catch { return res.status(401).json({ error: "Your session expired. Please sign in again." }); }
}
function adminOnly(req, res, next) { if (req.user?.role !== "admin" || req.user.email !== ADMIN) return res.status(403).json({ error: "Super Administrator access required." }); next(); }
async function tmOnly(req, res, next) {
  if (req.user?.role !== "tm") return res.status(403).json({ error: "Tournament Manager access required." });
  const q = await pool.query("SELECT active FROM tm_accounts WHERE email=$1", [req.user.email]);
  if (!q.rows[0]?.active) return res.status(403).json({ error: "Your TM account is inactive. Contact the administrator." });
  next();
}
async function audit(actor, action, entity, id, details = {}) {
  await pool.query("INSERT INTO audit_logs(actor,action,entity_type,entity_id,details) VALUES($1,$2,$3,$4,$5::jsonb)", [actor, action, entity, id || null, JSON.stringify(details)]);
}
app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/api/session", identify, async (req, res) => res.json({ email: req.user.email, role: req.user.role }));
app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !password) return res.status(400).json({ error: "Enter your email address and password." });
    let role = "tm", account;
    if (email === ADMIN) {
      role = "admin";
      const q = await pool.query("SELECT email,password_hash FROM app_admins WHERE email=$1", [ADMIN]);
      account = q.rows[0];
      if (!account?.password_hash) return res.status(503).json({ error: "Super Admin password is not configured. Add ADMIN_PASSWORD in Render Environment." });
    } else {
      const q = await pool.query("SELECT email,password_hash,active FROM tm_accounts WHERE email=$1", [email]);
      account = q.rows[0];
      if (!account?.active || !account.password_hash) return res.status(403).json({ error: "This TM account is inactive or has no password. Contact the Super Administrator." });
    }
    if (!(await bcrypt.compare(password, account.password_hash))) return res.status(401).json({ error: "Incorrect email or password." });
    setSession(res, email, role);
    res.json({ ok: true, role, email });
  } catch (e) { console.error("Login error:", e); res.status(500).json({ error: "Unable to sign in right now." }); }
});
app.post("/api/auth/logout", (_req, res) => { res.clearCookie("dam_session", { path: "/" }); res.json({ ok: true }); });

app.get("/api/board", async (_req, res) => {
  const [teams, events, results, rules, settings] = await Promise.all([
    pool.query("SELECT id,name,division,color FROM teams WHERE active=true ORDER BY division,name"),
    pool.query("SELECT e.id,e.name,e.category,e.division,e.status,s.name AS sport FROM events e LEFT JOIN sports s ON s.id=e.sport_id WHERE e.active=true ORDER BY s.name,e.name"),
    pool.query("SELECT r.id,r.place,r.points,r.performance,r.remarks,r.reviewed_at,e.name AS event,e.category,e.division,t.name AS team,s.name AS sport FROM results r JOIN events e ON e.id=r.event_id JOIN teams t ON t.id=r.team_id LEFT JOIN sports s ON s.id=e.sport_id WHERE r.status='approved' ORDER BY r.reviewed_at DESC NULLS LAST,r.submitted_at DESC"),
    pool.query("SELECT place,points,medal FROM scoring_rules ORDER BY place"),
    pool.query("SELECT value FROM app_settings WHERE key='theme'")
  ]);
  res.json({ teams: teams.rows, events: events.rows, results: results.rows, rules: rules.rows, theme: settings.rows[0]?.value || {}, updatedAt: new Date().toISOString() });
});
app.get("/api/admin", identify, adminOnly, async (_req, res) => {
  const [teams,sports,events,pending,tms,rules,invites,auditRows,allResults] = await Promise.all([
    pool.query("SELECT * FROM teams ORDER BY division,name"),
    pool.query("SELECT * FROM sports ORDER BY name"),
    pool.query("SELECT e.*,s.name AS sport FROM events e LEFT JOIN sports s ON s.id=e.sport_id ORDER BY s.name,e.name"),
    pool.query("SELECT r.*,e.name AS event,e.category,t.name AS team,s.name AS sport FROM results r JOIN events e ON e.id=r.event_id JOIN teams t ON t.id=r.team_id LEFT JOIN sports s ON s.id=e.sport_id WHERE r.status='pending' ORDER BY r.submitted_at"),
    pool.query("SELECT * FROM tm_accounts ORDER BY display_name,email"),
    pool.query("SELECT * FROM scoring_rules ORDER BY place"),
    pool.query("SELECT email,display_name,invited_at,active FROM invited_users ORDER BY invited_at DESC"),
    pool.query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200"),
    pool.query("SELECT r.*,e.name AS event,e.category,t.name AS team,s.name AS sport FROM results r JOIN events e ON e.id=r.event_id JOIN teams t ON t.id=r.team_id LEFT JOIN sports s ON s.id=e.sport_id ORDER BY r.submitted_at DESC LIMIT 300")
  ]);
  res.json({ admin: { email: ADMIN, display_name: "Super Administrator" }, teams: teams.rows, sports: sports.rows, events: events.rows, pending: pending.rows, results: allResults.rows, tms: tms.rows, rules: rules.rows, invites: invites.rows, audit: auditRows.rows });
});
app.post("/api/admin", identify, adminOnly, async (req, res) => {
  const b = req.body || {}; const action = String(b.action || "");
  if (action === "team") {
    if (!String(b.name || "").trim()) return res.status(400).json({ error: "Team name required." });
    await pool.query("INSERT INTO teams(name,division,color) VALUES($1,$2,$3) ON CONFLICT(name) DO UPDATE SET division=EXCLUDED.division,color=EXCLUDED.color,active=true", [b.name.trim(),b.division || "Overall",b.color || "#D7A94B"]);
  } else if (action === "sport") {
    if (!String(b.name || "").trim()) return res.status(400).json({ error: "Sport name required." });
    await pool.query("INSERT INTO sports(name) VALUES($1) ON CONFLICT(name) DO UPDATE SET active=true", [b.name.trim()]);
  } else if (action === "event") {
    if (!b.sport_id || !String(b.name || "").trim()) return res.status(400).json({ error: "Sport and event name required." });
    await pool.query("INSERT INTO events(sport_id,name,category,division) VALUES($1,$2,$3,$4)", [b.sport_id,b.name.trim(),b.category || "",b.division || "Overall"]);
  } else if (action === "scoring") {
    for (const r of (Array.isArray(b.rules) ? b.rules : [])) await pool.query("INSERT INTO scoring_rules(place,points,medal) VALUES($1,$2,$3) ON CONFLICT(place) DO UPDATE SET points=EXCLUDED.points,medal=EXCLUDED.medal", [Number(r.place),Number(r.points),r.medal || ""]);
  } else if (action === "tm") {
    const email = String(b.email || "").trim().toLowerCase();
    const password = String(b.password || "");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "Valid TM email required." });
    if (password.length < 10) return res.status(400).json({ error: "Set a temporary password with at least 10 characters." });
    const ids = Array.isArray(b.event_ids) ? b.event_ids : [];
    if (!ids.length) return res.status(400).json({ error: "Assign at least one event." });
    const passwordHash = await bcrypt.hash(password, 12);
    await pool.query("INSERT INTO invited_users(email,display_name,active) VALUES($1,$2,true) ON CONFLICT(email) DO UPDATE SET display_name=EXCLUDED.display_name,active=true", [email,b.display_name || email]);
    await pool.query("INSERT INTO tm_accounts(email,display_name,password_hash,active) VALUES($1,$2,$3,true) ON CONFLICT(email) DO UPDATE SET display_name=EXCLUDED.display_name,password_hash=EXCLUDED.password_hash,active=true", [email,b.display_name || email,passwordHash]);
    await pool.query("DELETE FROM tm_event_assignments WHERE email=$1", [email]);
    for (const id of ids) await pool.query("INSERT INTO tm_event_assignments(email,event_id) VALUES($1,$2) ON CONFLICT DO NOTHING", [email,id]);
  } else if (action === "manual-result") {
    const eventId=String(b.event_id||""), teamId=String(b.team_id||""), place=Number(b.place);
    if(!eventId||!teamId||!Number.isInteger(place)||place<1||place>8)return res.status(400).json({error:"Choose an event, team, and valid placement."});
    const [event,team,rule,duplicate]=await Promise.all([
      pool.query("SELECT id FROM events WHERE id=$1 AND active=true",[eventId]),
      pool.query("SELECT id FROM teams WHERE id=$1 AND active=true",[teamId]),
      pool.query("SELECT points FROM scoring_rules WHERE place=$1",[place]),
      pool.query("SELECT id FROM results WHERE event_id=$1 AND place=$2 AND status IN('pending','approved')",[eventId,place])
    ]);
    if(!event.rowCount)return res.status(400).json({error:"Select an active event."});
    if(!team.rowCount)return res.status(400).json({error:"Select an active team."});
    if(!rule.rowCount)return res.status(400).json({error:"No scoring rule exists for this placement."});
    if(duplicate.rowCount)return res.status(409).json({error:"A result for this event and placement already exists. Correct or delete it first."});
    const points=b.points===undefined||b.points===""?Number(rule.rows[0].points):Number(b.points);
    if(!Number.isFinite(points)||points<0)return res.status(400).json({error:"Enter valid non-negative points."});
    const q=await pool.query("INSERT INTO results(event_id,team_id,place,points,performance,remarks,submitted_by,status,reviewed_by,reviewed_at) VALUES($1,$2,$3,$4,$5,$6,$7,'approved',$7,now()) RETURNING id",[eventId,teamId,place,points,String(b.performance||"").slice(0,100),String(b.remarks||"").slice(0,500),ADMIN]);
    await audit(ADMIN,"manual-approved-result","result",q.rows[0].id,{event_id:eventId,team_id:teamId,place,points});
  } else return res.status(400).json({ error: "Unknown action." });
  await audit(ADMIN, action, "configuration", null, b);
  res.json({ ok: true });
});
app.put("/api/admin", identify, adminOnly, async (req, res) => {
  const b = req.body || {}; const id = String(b.id || "");
  if (b.action === "approve" || b.action === "reject") {
    const status = b.action === "approve" ? "approved" : "rejected";
    const q = await pool.query("UPDATE results SET status=$1,reviewed_by=$2,reviewed_at=now(),review_note=$3 WHERE id=$4 AND status='pending' RETURNING id", [status,ADMIN,b.note || "",id]);
    if (!q.rowCount) return res.status(404).json({ error: "Pending result not found." });
    await audit(ADMIN,status,"result",id,{note:b.note || ""});
    return res.json({ ok: true });
  }
  if (b.action === "tm-active") {
    await pool.query("UPDATE tm_accounts SET active=$1 WHERE email=$2", [!!b.active,String(b.email || "").toLowerCase()]);
    await pool.query("UPDATE invited_users SET active=$1 WHERE email=$2", [!!b.active,String(b.email || "").toLowerCase()]);
    await audit(ADMIN,"tm-active","tm",b.email,{active:!!b.active});
    return res.json({ ok: true });
  }
  if (b.action === "team-edit") {
    const q=await pool.query("UPDATE teams SET name=$1,division=$2,color=$3 WHERE id=$4 RETURNING id",[String(b.name||"").trim(),String(b.division||"Overall"),String(b.color||"#D7A94B"),id]);
    if(!q.rowCount)return res.status(404).json({error:"Team not found."});
    await audit(ADMIN,"update","team",id,{name:b.name,division:b.division,color:b.color});return res.json({ok:true});
  }
  if (b.action === "sport-edit") {
    const q=await pool.query("UPDATE sports SET name=$1 WHERE id=$2 RETURNING id",[String(b.name||"").trim(),id]);
    if(!q.rowCount)return res.status(404).json({error:"Sport not found."});
    await audit(ADMIN,"update","sport",id,{name:b.name});return res.json({ok:true});
  }
  if (b.action === "event-edit") {
    const q=await pool.query("UPDATE events SET sport_id=$1,name=$2,category=$3,division=$4,status=$5 WHERE id=$6 RETURNING id",[b.sport_id||null,String(b.name||"").trim(),String(b.category||""),String(b.division||"Overall"),["scheduled","in_progress","completed"].includes(b.status)?b.status:"scheduled",id]);
    if(!q.rowCount)return res.status(404).json({error:"Event not found."});
    await audit(ADMIN,"update","event",id,{name:b.name,category:b.category,division:b.division});return res.json({ok:true});
  }
  if (b.action === "result-edit") {
    const q=await pool.query("UPDATE results SET event_id=$1,team_id=$2,place=$3,points=$4,performance=$5,remarks=$6,status='pending',reviewed_by=NULL,reviewed_at=NULL,review_note=NULL WHERE id=$7 RETURNING id",[b.event_id,b.team_id,Number(b.place),Number(b.points),String(b.performance||"").slice(0,100),String(b.remarks||"").slice(0,500),id]);
    if(!q.rowCount)return res.status(404).json({error:"Result not found."});
    await audit(ADMIN,"correct-and-requeue","result",id,{event_id:b.event_id,team_id:b.team_id,place:b.place});return res.json({ok:true,message:"Corrected result returned to pending approval."});
  }
  res.status(400).json({ error: "Unknown update." });
});
app.delete("/api/admin", identify, adminOnly, async (req, res) => {
  const b=req.body||{}, action=String(b.action||""), id=String(b.id||"");
  if(action==="tm"){const email=String(b.email||"").toLowerCase();await pool.query("UPDATE tm_accounts SET active=false WHERE email=$1",[email]);await pool.query("UPDATE invited_users SET active=false WHERE email=$1",[email]);await audit(ADMIN,"tm-disabled","tm",email);return res.json({ok:true})}
  if(action==="team"){const q=await pool.query("UPDATE teams SET active=false WHERE id=$1 RETURNING id",[id]);if(!q.rowCount)return res.status(404).json({error:"Team not found."});await audit(ADMIN,"archive","team",id);return res.json({ok:true,message:"Team archived; historical results retained."})}
  if(action==="sport"){const q=await pool.query("UPDATE sports SET active=false WHERE id=$1 RETURNING id",[id]);if(!q.rowCount)return res.status(404).json({error:"Sport not found."});await audit(ADMIN,"archive","sport",id);return res.json({ok:true,message:"Sport archived."})}
  if(action==="event"){const q=await pool.query("UPDATE events SET active=false WHERE id=$1 RETURNING id",[id]);if(!q.rowCount)return res.status(404).json({error:"Event not found."});await audit(ADMIN,"archive","event",id);return res.json({ok:true,message:"Event archived; historical results retained."})}
  if(action==="result"){const q=await pool.query("DELETE FROM results WHERE id=$1 RETURNING id,event_id,team_id,place,points,status,submitted_by",[id]);if(!q.rowCount)return res.status(404).json({error:"Result not found."});await audit(ADMIN,"delete","result",id,q.rows[0]);return res.json({ok:true,message:"Result deleted and recorded in the audit log."})}
  return res.status(400).json({error:"Choose a supported record to remove."});
});
app.get("/api/tm", identify, tmOnly, async (req, res) => {
  const email = req.user.email;
  const [events,submissions,teams,rules] = await Promise.all([
    pool.query("SELECT e.id,e.name,e.category,e.division,s.name AS sport FROM tm_event_assignments a JOIN events e ON e.id=a.event_id LEFT JOIN sports s ON s.id=e.sport_id WHERE a.email=$1 AND e.active=true ORDER BY s.name,e.name", [email]),
    pool.query("SELECT r.id,r.place,r.points,r.status,r.submitted_at,r.performance,r.remarks,e.name AS event,t.name AS team FROM results r JOIN events e ON e.id=r.event_id JOIN teams t ON t.id=r.team_id WHERE lower(r.submitted_by)=lower($1) ORDER BY r.submitted_at DESC LIMIT 50", [email]),
    pool.query("SELECT id,name,division FROM teams WHERE active=true ORDER BY name"),
    pool.query("SELECT place,points,medal FROM scoring_rules ORDER BY place")
  ]);
  res.json({ tm: { email }, events: events.rows, submissions: submissions.rows, teams: teams.rows, rules: rules.rows });
});
app.post("/api/tm", identify, tmOnly, async (req, res) => {
  const { event_id, team_id, place, performance = "", remarks = "" } = req.body || {};
  const assigned = await pool.query("SELECT 1 FROM tm_event_assignments WHERE email=$1 AND event_id=$2", [req.user.email,event_id]);
  if (!assigned.rowCount) return res.status(403).json({ error: "This event is not assigned to your account." });
  const rule = await pool.query("SELECT points FROM scoring_rules WHERE place=$1", [Number(place)]);
  if (!rule.rowCount) return res.status(400).json({ error: "No scoring rule exists for this placement." });
  const team = await pool.query("SELECT id FROM teams WHERE id=$1 AND active=true", [team_id]);
  if (!team.rowCount) return res.status(400).json({ error: "Select a valid active team." });
  const duplicate = await pool.query("SELECT id FROM results WHERE event_id=$1 AND place=$2 AND status IN('pending','approved')", [event_id,Number(place)]);
  if (duplicate.rowCount) return res.status(409).json({ error: "A result for this placement is already pending or approved." });
  const q = await pool.query("INSERT INTO results(event_id,team_id,place,points,performance,remarks,submitted_by) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id", [event_id,team_id,Number(place),rule.rows[0].points,String(performance).slice(0,100),String(remarks).slice(0,500),req.user.email]);
  await audit(req.user.email,"submit","result",q.rows[0].id,{event_id,team_id,place:Number(place)});
  res.json({ ok: true, id: q.rows[0].id, message: "Result submitted for administrator approval." });
});
app.get("/api/audit", identify, adminOnly, async (_req,res) => { const q = await pool.query("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 200"); res.json({ rows:q.rows }); });
app.put("/api/theme", identify, adminOnly, async (req,res) => {
  const value = req.body || {};
  await pool.query("INSERT INTO app_settings(key,value,updated_at) VALUES('theme',$1::jsonb,now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()", [JSON.stringify(value)]);
  await audit(ADMIN,"theme-updated","settings",null,{keys:Object.keys(value)});
  res.json({ok:true});
});
app.get("/api/live", async (_req,res)=>{const q=await pool.query("SELECT value FROM app_settings WHERE key='live_bulletin'");res.json(q.rows[0]?.value||{title:"Division Athletic Meet",subtitle:"Official Live Coverage",venue:"",schedule:"",streamUrl:"",isLive:false})});
app.put("/api/live", identify, adminOnly, async (req,res)=>{
 const b=req.body||{},url=String(b.streamUrl||"").trim();
 if(url&&!/^https?:\/\/(www\.)?(facebook\.com|fb\.watch)\//i.test(url))return res.status(400).json({error:"Use a public Facebook video or Facebook Live post URL."});
 const value={title:String(b.title||"Division Athletic Meet").slice(0,120),subtitle:String(b.subtitle||"Official Live Coverage").slice(0,180),venue:String(b.venue||"").slice(0,180),schedule:String(b.schedule||"").slice(0,180),streamUrl:url,isLive:!!b.isLive};
 await pool.query("INSERT INTO app_settings(key,value,updated_at) VALUES('live_bulletin',$1::jsonb,now()) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value,updated_at=now()",[JSON.stringify(value)]);
 await audit(ADMIN,"live-bulletin-updated","settings",null,{isLive:value.isLive,hasStream:!!url});res.json({ok:true,value});
});
app.get("/live",(_req,res)=>res.sendFile(path.join(__dirname,"public","live.html")));
app.get("/login", (_req,res) => res.sendFile(path.join(__dirname,"public","login.html")));
app.get("*", (_req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
app.use((err,_req,res,_next) => { console.error(err); res.status(500).json({error:"An unexpected server error occurred."}); });
const port = Number(process.env.PORT || 10000);
init().then(() => app.listen(port, "0.0.0.0", () => console.log("Division Athletic Meet listening on " + port))).catch(e => { console.error("Database initialization failed",e); process.exit(1); });
