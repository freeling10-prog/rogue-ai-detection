#!/usr/bin/env python3
"""Serial Context.dev lead harvester for AgentGate.

Usage:
    python3 marketing/harvest_context_dev.py <state_dir> <repo_root> [max_seconds] [credit_floor]

- <state_dir> holds local working files (state.json, verified.csv, batch_NNN.csv).
  Keep it OUTSIDE the repo: those files contain prospect names and emails.
- Only marketing/suppression_hashes.json (SHA-256 hashes) is written to the repo.
- Context.dev auth is injected by the network proxy; no API key is stored here.
- Set HARVEST_COMMIT_TRAILER to append attribution lines to hash-update commits.

Strictly one request at a time; honors Retry-After on 429. Exits (status file
says why) when 25 new companies pass verification, when a 5,000-credit
checkpoint is crossed, when credits hit the floor, or when the time budget ends.
Re-running resumes from state.json.
"""
import csv, hashlib, json, os, re, ssl, subprocess, sys, time, urllib.error, urllib.parse, urllib.request

HDIR = sys.argv[1]            # harvest state dir (scratchpad)
REPO = sys.argv[2]            # repo root
MAX_SECONDS = int(sys.argv[3]) if len(sys.argv) > 3 else 6600
BATCH_SIZE, CHECKPOINT = 25, 5000
FLOOR = int(sys.argv[4]) if len(sys.argv) > 4 else 50
BASE = "https://api.context.dev/v1"
CA = "/root/.ccr/ca-bundle.crt"
CTX = ssl.create_default_context(cafile=CA) if os.path.exists(CA) else None
HASHES = os.path.join(REPO, "marketing", "suppression_hashes.json")
STATE = os.path.join(HDIR, "state.json")
VERIFIED = os.path.join(HDIR, "verified.csv")
REJECTS = os.path.join(HDIR, "rejects.csv")
STATUS = os.path.join(HDIR, "status.json")
LOG = os.path.join(HDIR, "harvest.log")
FIELDS = ["date", "company", "domain", "email", "email_source", "hook", "quote", "quote_source", "tier", "description"]

def log(m):
    line = f"[{time.strftime('%H:%M:%S')}] {m}"
    print(line, flush=True)
    with open(LOG, "a") as f: f.write(line + "\n")

# ---------------- HTTP (serial, Retry-After aware) ----------------
calls = 0
def req(method, path, body=None, params=None, tries=0):
    global calls
    url = BASE + path + ("?" + urllib.parse.urlencode(params) if params else "")
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method,
                               headers={"Content-Type": "application/json", "Authorization": "Bearer dummy"})
    calls += 1
    try:
        with urllib.request.urlopen(r, timeout=90, context=CTX) as f:
            return json.loads(f.read())
    except urllib.error.HTTPError as e:
        if e.code == 429 and tries < 8:
            ra = e.headers.get("Retry-After")
            wait = float(ra) if ra and ra.replace(".", "").isdigit() else 5 * (2 ** tries)
            log(f"429 on {path}; sleeping {wait:.0f}s (Retry-After={ra})")
            time.sleep(min(wait, 300)); return req(method, path, body, params, tries + 1)
        if e.code >= 500 and tries < 2:
            time.sleep(5); return req(method, path, body, params, tries + 1)
        try: return {"_error": e.code, **json.loads(e.read())}
        except Exception: return {"_error": e.code}
    except Exception as e:
        if tries < 2:
            time.sleep(5); return req(method, path, body, params, tries + 1)
        return {"_error": str(e)}

def credits():
    u = req("GET", "/org/usage")
    return u.get("credits_remaining")

def markdown(url):
    r = req("GET", "/web/scrape/markdown", params={"url": url, "includeLinks": "false"})
    return r.get("markdown") or ""

# ---------------- text helpers ----------------
def clean(t):
    t = re.sub(r"!\[[^\]]*\]\([^)]*\)", " ", t)
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"\\\\|[*_`#>|]", " ", t)
    t = t.replace("\\", " ")
    return re.sub(r"\s+", " ", t).strip()

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
BANNED = ("jobs", "careers", "career", "press", "privacy", "orders", "billing", "security", "legal", "abuse",
          "noreply", "no-reply", "donotreply", "dpo", "dpa", "academic", "creators", "students", "education", "affiliates", "demo", "demos", "inquirieshello", "emailinfo", "hola", "kontakt", "hiring", "activate", "invest", "biz", "iod", "ps", "sys", "rodo", "ventas", "vendas", "verkauf", "hotline", "enquiries", "callinfo", "servicio", "emailhello", "expertshello", "gdpr", "media", "hr", "recruit", "talent", "dmca",
          "compliance", "accessibility", "unsubscribe", "vulnerability", "disclosure", "bugbounty", "bounty",
          "copyright", "terms", "invoice", "accounts", "payable", "receivable", "finance", "trust", "ethics",
          "whistle", "data-protection", "dataprotection", "optout", "opt-out", "pr", "marketing", "events",
          "webmaster", "postmaster", "hostmaster", "admin", "root", "example", "test", "your", "name", "email",
          "user", "john", "jane", "firstname", "first.last", "first")
STRONG_BAN = ("legal", "privacy", "datenschutz", "contract", "notice", "compliance", "security", "abuse", "dmca",
              "gdpr", "linkedin", "admin", "careers", "jobs", "press", "billing", "invoice", "unsubscribe", "noreply",
              "donotreply", "dpo", "rgpd", "impressum", "copyright", "trademark", "subpoena", "lawenforcement", "deactivat", "delet", "removal", "cancel", "deployments", "investor", "demo")
RANK = [("founders", 0), ("founder", 0), ("ceo", 0), ("sales", 1), ("hello", 2), ("hi", 2), ("team", 2),
        ("contact", 2), ("info", 3), ("partners", 4), ("partnerships", 4), ("support", 5), ("help", 5)]

def good_emails(text, domain):
    root = domain.lower().replace("www.", "")
    out = {}
    for e in EMAIL.findall(text or ""):
        e = e.lower().strip(".")
        local, _, host = e.partition("@")
        if not (host == root or host.endswith("." + root)): continue
        if host.endswith(".pec.it") or re.search(r"\.(png|jpe?g|svg|webp|gif)$", e): continue
        if local in BANNED or any(local.startswith(b + ".") or local.startswith(b + "-") for b in BANNED): continue
        if re.fullmatch(r"[a-f0-9]{16,}", local): continue
        lc = re.sub(r"[^a-z]", "", local)
        if any(w in lc for w in STRONG_BAN): continue
        rank = next((r for k, r in RANK if local == k), None)
        if rank is None:
            rank = 0 if re.fullmatch(r"[a-z]{2,15}", local) else 6   # personal first-name address
        out[e] = rank
    return out

AGENCY = re.compile(r"\b(agency|agencies|consultancy|consulting firm|consulting services|development company|dev shop|"
                    r"software house|outsourc\w*|staff augmentation|white[- ]label|nearshore|offshore development|"
                    r"we build (?:apps|software|websites) for|hire (?:our )?developers|digital transformation partner|custom software|"
                    r"engineering practice|we advise|advisory|implementation partner|studio|freelanc\w*|contractor|"
                    r"build custom (?:MCP|AI|agents?)|for our clients|client work|we design and build|"
                    r"we build (?:multi-agent|AI|GenAI|LLM)[\w -]{0,20}(?:systems|solutions|products)|"
                    r"(?:automation|engineering|data|AI|software) (?:firm|services company)|available on request|we design B2B|software factory|"
                    r"we (?:build|deliver|design|implement) (?:custom )?(?:AI )?agents (?:that|and|for)|every engagement|"
                    r"AI services|builds? and implements?|implementation services|we help (?:early-stage )?(?:businesses|organi[sz]ations|companies|brands|startups|founders) |"
                    r"web/app products|tailored solutions|bespoke|"
                    r"I help (?:firms|businesses|companies|teams)|development team can|engineering company|solutions (?:firm|company|provider)|"
                    r"we design and run|ontwerpt|maatwerk|boutique|agency|consultanc\w*|technology solutions|we craft and deploy|"
                    r"senior engineers|desarrollamos|democratizamos|delivers AI agents and the front-end|we build and integrate|redesigns sales functions|transforms the software stack|development services|technology firm that delivers|services firm|its services|consulting partner|venture capital|we build multi[- ]agents?|designs, builds, tests|growth lab|as a service, creating|in real projects|builds custom AI agents for|AI-forward consult\w*)\b", re.I)
COMPETITOR = re.compile(r"\b(policy enforcement|enforced before they run|execution boundary|prompt injection (?:protection|defen[cs]e|firewall)|"
                        r"runtime control over (?:production )?AI agents|trust layer for AI|portable authorization|authorization (?:of|for) AI agents|trust layer for AI agents|secures, governs|assess and control (?:the )?MCP|discover, assess|\bNHIs?\b|non-human identit\w*|governs? AI agent tool access|governed MCP gateway|authority layer|identity registry for AI agents|trust is nowhere|assurance firm|AI assurance|defensive interpretability|governing autonomous AI agents|governance for (?:AI )?agents|pass the same checks|LLM firewall|kill switch|cybersecurity firm|security operations platform|SecOps|\bSOC\b|threat (?:detection|hunting)|security audits?|trust infrastructure|rug[- ]pull|tool poisoning|MCP vulnerabilit\w*|security platform for AI agents|control,? and security|AI control plane|untrusted (?:MCP )?tool calls|sandbox(?:es)? (?:that contains|for untrusted)|denied by default|policy engine for agents|"
                        r"penetration test\w*|pentest\w*|red[- ]team\w*|cybersecurity (?:company|assessment|services)|security assessment|"
                        r"AI (?:security|firewall)|guardrails? (?:platform|for agents)|agent security|MCP security|runtime protection)\b", re.I)
DIRECTORY = re.compile(r"\b(directory|archive|catalog of|list of|awesome|marketplace of free)\b", re.I)
HOOK = re.compile(r"\b(MCP|Model Context Protocol|AI agents?|agentic|autonomous agents?|agents? (?:that|can|to)|"
                  r"tool calls?|computer[- ]use|browser agents?|coding agents?)\b", re.I)
MCP = re.compile(r"\b(MCP|Model Context Protocol)\b")
SENSITIVE = re.compile(r"\b(health|clinical|patient|HIPAA|EHR|payments?|banking|bank|fintech|insurance|legal|payroll|"
                       r"invoice|payables|tax|medical|pharma|credit|lending|KYC|PHI|PII)\b", re.I)
BAD_QUOTE = re.compile(r"(^yes\b|^no\b|diagram|illustrat|gartner|forrester|by 20\d\d|rights reserved|trademark|schedule a demo|by providing|you agree|cookie|privacy|©|copyright|sign up|log ?in|subscribe|newsletter|http|www\.|@|\.com/|"
                       r"learn more|read more|book a demo|get started|view all|toggle|menu)", re.I)

def pick_quote(md_text):
    full = clean(md_text)
    cands = []
    for raw in re.split(r"\n+", md_text):
        for piece in re.split(r"(?<=[.!?])\s+(?=[A-Z])", clean(raw)):
            q = piece.strip(" -–—:;,")
            if not (45 <= len(q) <= 210): continue
            if not HOOK.search(q) or BAD_QUOTE.search(q): continue
            if len(q.split()) < 8 or q.count("  ") or sum(c.isupper() for c in q) > len(q) * 0.35: continue
            if q not in full: continue
            if not re.match(r"[A-Z0-9\"']", q) or not re.search(r"[.!]$", q) or "?" in q: continue
            if re.search(r"[{}\[\]=<>]|\(\w*:|::", q): continue
            if len(re.findall(r"\b(the|and|to|your|a|of|for|with|in|is|it|on|every|any|that)\b", q, re.I)) < 2: continue
            if re.search(r"\b[A-Z][a-z]+ [A-Z][a-z]+ [A-Z][a-z]+\b", q) and not MCP.search(q[:3]): continue
            if re.search(r"\b(or|and|the|to|for|with|a|an|of|your|in|on|at|by|from|that|is|are)$", q, re.I): continue
            if q.count('"') % 2 or q.count("(") != q.count(")"): continue
            score = (0 if MCP.search(q) else 1, abs(len(q) - 120))
            cands.append((score, q))
    cands.sort()
    return cands[0][1] if cands else None

def tier(hook, text):
    if hook == "MCP": return 950
    return 750 if SENSITIVE.search(text) else 450

# ---------------- dedup ----------------
def h(s): return hashlib.sha256(s.encode()).hexdigest()
def norm_name(s): return re.sub(r"[^a-z0-9]", "", s.lower())
def load_hashes():
    d = json.load(open(HASHES))
    return d, set(d["company_hashes"]), set(d["email_hashes"]), set(d["domain_hashes"])
SUFFIX = re.compile(r"(labs?|ai|hq|inc|llc|ltd|technologies|technology|tech|software|systems|io|app|cloud|co|the|get|try|use|go)$")
def name_variants(name, dom):
    out = set()
    n = norm_name(name or "")
    if n: out.add(n)
    for _ in range(3):
        n2 = SUFFIX.sub("", n)
        if n2 and n2 != n: out.add(n2); n = n2
    label = dom.split(".")[0]
    for v in {label, re.sub(r"^(get|try|use|go|join|hey|with)", "", label), re.sub(r"(ai|hq|app|labs?|io)$", "", label)}:
        v = norm_name(v)
        if len(v) >= 2: out.add(v)
    return out
def root_domain(d):
    d = d.lower().strip().split("/")[0]
    return d[4:] if d.startswith("www.") else d

BIG = set("""google.com microsoft.com amazon.com aws.amazon.com salesforce.com oracle.com ibm.com sap.com adobe.com
atlassian.com servicenow.com shopify.com stripe.com openai.com anthropic.com cloudflare.com vercel.com github.com
gitlab.com datadoghq.com pagerduty.com intercom.com zendesk.com hubspot.com notion.so slack.com zapier.com
twilio.com okta.com snowflake.com databricks.com mongodb.com elastic.co hashicorp.com""".split())

# ---------------- discovery queries ----------------
VERTS = [
 "AI SRE agents that remediate production incidents", "AI agents that execute DevOps runbooks",
 "AI agents for Kubernetes operations", "AI agents for cloud cost and infrastructure changes",
 "AI data analyst agents that run SQL on the warehouse", "AI agents for Postgres and database operations",
 "AI agents for clinical workflows and EHR tasks", "AI agents for healthcare revenue cycle and prior authorization",
 "AI agents for pharmacy and life sciences operations", "AI customer support agents that issue refunds in Shopify",
 "AI agents for eCommerce operations and order management", "AI agents for returns and post-purchase support",
 "autonomous coding agents that open pull requests", "AI agents for codebase migration and refactoring",
 "AI code review agents", "browser automation agents for enterprises", "computer-use agent infrastructure",
 "hosted MCP server platforms", "MCP gateways and MCP server marketplaces", "AI agents for accounts payable and invoices",
 "AI agents for bookkeeping and accounting", "AI agents for payments and fintech operations",
 "AI agents for insurance claims", "AI agents for legal document review", "AI agents for HR and payroll systems",
 "AI agents for sales and CRM updates", "AI agents for marketing and ad spend management",
 "AI agents for IT helpdesk and identity tasks", "AI agents for security operations triage",
 "AI agents for procurement and supply chain", "AI agents for real estate and property management",
 "AI agents for logistics and freight", "AI agents for recruiting workflows", "AI agents that send email on behalf of users",
 "AI agents for calendar and scheduling", "AI agents for document processing and data extraction",
 "multi-agent orchestration platforms", "agent-to-agent communication platforms", "AI agent builders for enterprises",
 "voice AI agents that take actions in business systems",
]
FRAMES = [
 "Startups building {v} that offer an MCP server",
 "Early-stage B2B startups building {v}",
 "Seed or Series A companies selling {v} to businesses",
 "YC-backed companies building {v}",
]
VERTS2 = [
 "AI agents for tax preparation and compliance", "AI agents for KYC and AML compliance", "AI agents for treasury and cash management",
 "AI agents for wealth management advisors", "AI agents for mortgage processing", "AI agents for commercial lending",
 "AI agents for dental and veterinary practices", "AI agents for clinical trials operations", "AI agents for medical coding",
 "AI agents for government and public sector services", "AI agents for education administration", "AI agents for hospitality and hotels",
 "AI agents for travel booking", "AI agents for field service and maintenance", "AI agents for construction project management",
 "AI agents for energy and utilities operations", "AI agents for telecom network operations", "AI agents for data engineering pipelines",
 "AI agents for QA and software testing", "AI agents for API integration and iPaaS", "AI agents for Salesforce administration",
 "AI agents for ServiceNow and ITSM", "AI agents for Jira and project tracking", "AI agents for GitHub repository maintenance",
 "AI agents for incident postmortems and on-call", "AI agents for cloud security posture fixes", "AI agents for database migrations",
 "AI agents for spreadsheets and Excel automation", "AI agents for contract management", "AI agents for customer onboarding",
 "AI agents for churn prevention and customer success", "AI agents for social media management", "AI agents for content and SEO publishing",
 "AI agents for podcast and video production", "AI agents for translation and localization", "AI agents for research and web browsing",
 "AI agents for CRM data enrichment", "AI agents for outbound sales prospecting", "AI agents for event management", "AI agents for nonprofit fundraising",
]
FRAMES2 = [
 "Companies whose product includes an MCP server for {v}",
 "Startups founded in 2024 or 2025 building {v}",
 "B2B SaaS companies that added AI agent features for {v}",
]
CATS3 = [
 "CRM", "help desk and ticketing", "project management", "accounting and bookkeeping", "payroll", "HRIS", "applicant tracking",
 "ecommerce platforms", "inventory management", "ERP", "procurement", "expense management", "invoicing and billing", "payments",
 "banking APIs", "insurance software", "EHR and practice management", "pharmacy software", "legal practice management",
 "contract lifecycle management", "e-signature", "document management", "knowledge base", "wiki and docs", "note taking",
 "calendar and scheduling", "email marketing", "marketing automation", "ad platforms", "SEO tools", "social media management",
 "analytics and BI", "product analytics", "data warehouse", "ETL and data pipelines", "databases", "vector databases",
 "search APIs", "web scraping", "browser automation", "observability and monitoring", "incident management", "feature flags",
 "CI/CD", "code hosting", "code review", "API gateways", "cloud cost management", "infrastructure as code", "secrets management",
 "identity and SSO", "customer data platforms", "customer success", "sales engagement", "call center and telephony", "SMS and messaging APIs",
 "real estate software", "property management", "construction software", "field service management", "logistics and shipping",
 "travel and booking", "hospitality and hotel software", "restaurant POS", "education and LMS", "nonprofit CRM", "design tools",
 "video and media platforms", "translation and localization", "forms and surveys", "spreadsheets", "workflow automation",
]
CATS4 = [
 "agent payments and wallets", "x402 and stablecoin payments for agents", "agentic checkout", "AI agent spending controls",
 "open banking APIs for AI", "brokerage and trading APIs for agents", "insurance quoting APIs", "lending and credit decisioning APIs",
 "healthcare data APIs", "FHIR and EHR integration platforms", "pharmacy and prescription APIs", "clinical documentation",
 "HR and payroll APIs", "background check APIs", "identity verification APIs", "email sending APIs for agents",
 "SMS and voice APIs for agents", "calendar booking APIs", "e-signature APIs", "document generation APIs",
 "file storage for agents", "agent memory", "knowledge management", "internal developer portals", "database branching",
 "serverless hosting", "VPS and cloud hosting", "domain and DNS management", "CDN and edge platforms", "log management",
]
FRAMES4 = [
 "Startups with an MCP server for {c}",
 "Developer platforms for {c} that AI agents can call",
]
FRAMES3 = [
 "SaaS companies that launched an official MCP server for their {c} product",
 "Startups offering a hosted remote MCP server for {c}",
 "Companies whose {c} product lets AI agents take write actions via API or MCP",
]
def queries():
    for f in FRAMES:
        for v in VERTS:
            yield f.format(v=v)
    for f in FRAMES2:
        for v in VERTS + VERTS2:
            yield f.format(v=v)
    for f in FRAMES:
        for v in VERTS2:
            yield f.format(v=v)
    for f in FRAMES3:
        for c in CATS3:
            yield f.format(c=c)
    for f in FRAMES4:
        for c in CATS4:
            yield f.format(c=c)

# ---------------- verification ----------------
CONTACT_PATHS = ["/contact", "", "/about", "/contact-us", "/company", "/privacy", "/terms", "/support"]

def verify(company):
    dom = root_domain(company["domain"])
    desc = company.get("description") or ""
    if AGENCY.search(desc): return None, "agency (description)"
    if COMPETITOR.search(desc): return None, "competitor (AI/MCP security)"
    if DIRECTORY.search(desc) and not re.search(r"\bour (?:own )?MCP server\b", desc, re.I): return None, "directory"
    home = markdown(f"https://{dom}")
    if len(home) < 400: return None, "no live homepage"
    hc = clean(home)
    if len(AGENCY.findall(hc)) >= 2: return None, "agency (homepage)"
    if len(COMPETITOR.findall(hc)) >= 2: return None, "competitor (homepage)"
    if not HOOK.search(hc): return None, "no agent/MCP hook on homepage"
    quote = pick_quote(home)
    if not quote: return None, "no clean quotable hook line"
    hook = "MCP" if MCP.search(hc) else "agent"
    best = None
    for p in CONTACT_PATHS:
        t = home if p == "" else markdown(f"https://{dom}{p}")
        for e, r in good_emails(t, dom).items():
            if best is None or r < best[1]: best = (e, r, f"{dom}{p or '/'}")
        if best and best[1] <= 2: break
    if not best: return None, "no allowed published email on own domain"
    return {"date": time.strftime("%Y-%m-%d"), "company": company.get("name") or dom, "domain": dom,
            "email": best[0], "email_source": best[2], "hook": hook, "quote": quote,
            "quote_source": f"https://{dom}/", "tier": tier(hook, hc + " " + desc),
            "description": re.sub(r"\s+", " ", desc)[:240]}, "ok"

# ---------------- persistence ----------------
def load_state():
    if os.path.exists(STATE): return json.load(open(STATE))
    return {"q_index": 0, "cursor": None, "pages_on_q": 0, "seen": [], "start_credits": None,
            "next_checkpoint": None, "batch_no": 0, "pending": 0, "checkpoints": []}
def save_state(s):
    tmp = STATE + ".tmp"; json.dump(s, open(tmp, "w")); os.replace(tmp, STATE)
def append_csv(path, row, fields):
    new = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        if new: w.writeheader()
        w.writerow(row)

def flush_batch(state, rows):
    state["batch_no"] += 1
    bpath = os.path.join(HDIR, f"batch_{state['batch_no']:03d}.csv")
    with open(bpath, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS); w.writeheader(); w.writerows(rows)
    d, ch, eh, dh = load_hashes()
    for r in rows:
        for v in name_variants(r["company"], r["domain"]): ch.add(h(v))
        eh.add(h(r["email"])); dh.add(h(r["domain"]))
    d["company_hashes"], d["email_hashes"], d["domain_hashes"] = sorted(ch), sorted(eh), sorted(dh)
    d["updated"] = time.strftime("%Y-%m-%d")
    json.dump(d, open(HASHES, "w"), indent=1)
    git = lambda *a: subprocess.run(["git", "-C", REPO, *a], capture_output=True, text=True)
    git("add", "marketing/suppression_hashes.json")
    msg = f"Update suppression hashes (harvest batch {state['batch_no']:03d})"
    trailer = os.environ.get("HARVEST_COMMIT_TRAILER", "")
    git("commit", "-q", "-m", msg + ("\n\n" + trailer if trailer else ""))
    for target in ("HEAD", "HEAD:main"):
        for i in range(4):
            r = git("push", "-q", "origin", target)
            if r.returncode == 0: break
            time.sleep(2 ** (i + 1))
        else:
            log(f"push to {target} failed: {r.stderr.strip()[:200]}")
    log(f"batch {state['batch_no']:03d} written: {bpath}")
    return bpath

def main():
    t0 = time.time()
    os.makedirs(HDIR, exist_ok=True)
    s = load_state()
    seen = set(s["seen"])
    _, ch, eh, dh = load_hashes()
    c = credits()
    if c is None: log("cannot read credits; abort"); return finish(s, "error", None)
    if s["start_credits"] is None:
        s["start_credits"] = c; s["next_checkpoint"] = c - CHECKPOINT
    log(f"start: credits={c} next_checkpoint<={s['next_checkpoint']} batch_no={s['batch_no']}")
    pending = []
    if os.path.exists(os.path.join(HDIR, "pending.json")):
        pending = json.load(open(os.path.join(HDIR, "pending.json")))
    qs = list(queries())
    checked_since_usage = 0
    while True:
        if s["q_index"] >= len(qs): return finish(s, "queries_exhausted", c)
        q = qs[s["q_index"]]
        body = {"query": q, "mode": "fast"}
        if s["cursor"]: body["cursor"] = s["cursor"]
        r = req("POST", "/company/search", body)
        results = r.get("results") or []
        s["cursor"] = r.get("next_cursor"); s["pages_on_q"] += 1
        if not results or not s["cursor"] or s["pages_on_q"] >= 6:
            s["q_index"] += 1; s["cursor"] = None; s["pages_on_q"] = 0
        for comp in results:
            dom = root_domain(comp.get("domain") or "")
            if not dom or dom in seen or dom in BIG: continue
            seen.add(dom)
            if h(dom) in dh or any(h(v) in ch for v in name_variants(comp.get("name"), dom)): continue
            row, why = verify(comp)
            if row and h(row["email"]) in eh: row, why = None, "email already contacted"
            if row:
                pending.append(row); append_csv(VERIFIED, row, FIELDS)
                ch.add(h(norm_name(row["company"]))); dh.add(h(dom)); eh.add(h(row["email"]))
                log(f"PASS {row['company']} <{row['email']}> [{row['hook']}/{row['tier']}] \"{row['quote'][:70]}\"")
            else:
                append_csv(REJECTS, {"domain": dom, "reason": why}, ["domain", "reason"])
            s["seen"] = sorted(seen)
            json.dump(pending, open(os.path.join(HDIR, "pending.json"), "w"))
            save_state(s)
            checked_since_usage += 1
            if checked_since_usage >= 10:
                checked_since_usage = 0
                c = credits() or c
                if c <= FLOOR:
                    if pending: flush_batch(s, pending); pending = []; json.dump([], open(os.path.join(HDIR, "pending.json"), "w"))
                    return finish(s, "credit_floor", c)
                if c <= s["next_checkpoint"]:
                    s["checkpoints"].append({"at": time.strftime("%Y-%m-%dT%H:%M:%S"), "credits": c})
                    s["next_checkpoint"] -= CHECKPOINT; save_state(s)
                    log(f"CHECKPOINT crossed at credits={c}")
                    if pending: flush_batch(s, pending); pending = []; json.dump([], open(os.path.join(HDIR, "pending.json"), "w"))
                    return finish(s, "checkpoint", c)
            if len(pending) >= BATCH_SIZE:
                flush_batch(s, pending); pending = []
                json.dump([], open(os.path.join(HDIR, "pending.json"), "w")); save_state(s)
                return finish(s, "batch_ready", credits())
            if time.time() - t0 > MAX_SECONDS:
                return finish(s, "time_budget", credits())
        save_state(s)

def finish(s, why, c):
    save_state(s)
    st = {"reason": why, "credits_remaining": c, "batch_no": s["batch_no"], "calls_this_run": calls,
          "q_index": s["q_index"], "checkpoints": s["checkpoints"], "at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    json.dump(st, open(STATUS, "w"), indent=1)
    log(f"EXIT {why}: {st}")

if __name__ == "__main__":
    main()
