#!/usr/bin/env python3
"""
Ship-Ready Scan: free security scanner for AI-built apps.
https://github.com/shipreadycheck-dev/shipready-scan

Reads a project folder (never executes it) and flags the common ways
vibe-coded apps leak keys, data or money. Standard library only.

Usage:
    python3 shipready_scan.py <path> [--json out.json]

Output is a list of findings for a human or agent to confirm.
A finding is a lead, not a verdict. Confirm each one by reading the code.
"""
import argparse
import json
import os
import re
import sys

SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", ".venv", "venv",
             "__pycache__", ".turbo", ".vercel", "coverage", ".svelte-kit", ".nuxt"}
TEXT_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".py",
            ".json", ".env", ".sql", ".rules", ".html", ".yml", ".yaml", ".toml",
            ".gd", ".cs", ".txt", ".md", ".astro"}
MAX_BYTES = 1_000_000

FRONTEND_HINTS = ("src/", "app/", "pages/", "components/", "public/", "client/", "frontend/", "web/")
SERVER_HINTS = ("api/", "server/", "functions/", "supabase/functions", "backend/", "route.", "/routes/", "edge")

# (id, severity, title, regex, why, fix)
SECRET_PATTERNS = [
    ("secret.openai", "Critical", "OpenAI secret key in code",
     r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}",
     "Anyone who finds this key can run AI requests on your bill.",
     "Move it to a server-side environment variable, call OpenAI only from your server, and rotate the key in the OpenAI dashboard now."),
    ("secret.anthropic", "Critical", "Anthropic secret key in code",
     r"sk-ant-[A-Za-z0-9_\-]{20,}",
     "Anyone who finds this key can run AI requests on your bill.",
     "Move it to a server-side environment variable and rotate the key in the Anthropic Console now."),
    ("secret.stripe_live", "Critical", "Stripe live secret key in code",
     r"(?:sk|rk)_live_[A-Za-z0-9]{16,}",
     "This key can issue refunds, read customers and move money on your Stripe account.",
     "Rotate it in the Stripe dashboard now and load it only from a server-side environment variable."),
    ("secret.stripe_test", "Low", "Stripe test secret key in code",
     r"sk_test_[A-Za-z0-9]{16,}",
     "Test keys can't move real money, but this habit usually leaks the live key later.",
     "Load it from an environment variable instead."),
    ("secret.aws", "Critical", "AWS access key in code",
     r"AKIA[0-9A-Z]{16}",
     "AWS keys are scraped from public code within minutes and used to run up large bills.",
     "Deactivate the key in AWS IAM now and use environment variables or a secrets manager."),
    ("secret.github", "Critical", "GitHub token in code",
     r"gh[pousr]_[A-Za-z0-9]{36,}",
     "This token can read or change your repositories.",
     "Revoke it in GitHub settings now."),
    ("secret.google", "High", "Google API key in code",
     r"AIza[0-9A-Za-z_\-]{35}",
     "Google keys meant to be public (Maps) gain access to paid AI if Gemini is enabled on the same project.",
     "Restrict the key to specific APIs and websites in Google Cloud, and never enable Gemini on a project with public keys."),
    ("secret.db_url", "Critical", "Database URL with password in code",
     r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^\s:'\"]+:[^\s@'\"]+@[^\s'\"]+",
     "This gives direct access to your whole database, bypassing every app rule.",
     "Change the database password now and load the URL from a server-side environment variable."),
    ("secret.private_key", "Critical", "Private key file contents in code",
     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
     "Private keys let someone impersonate your server or service account.",
     "Remove it from the repo, rotate it, and store it in your host's secret settings."),
]

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")
_PUB_NAME = r"(NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|OPENAI|ANTHROPIC|GEMINI|DATABASE_URL|PASSWORD)[A-Z0-9_]*"
# Only real env-var usage: `KEY=...` lines (env files, shell, CI) or `env.KEY` / `env["KEY"]` in code.
PUBLIC_PREFIX_SECRET_RES = [
    re.compile(r"^[ \t]*(?:export[ \t]+)?(?P<name>" + _PUB_NAME + r")[ \t]*[=:]", re.M),
    re.compile(r"env(?:\.|\[[\"'])(?P<name>" + _PUB_NAME + r")\b"),
]


def is_frontend(rel):
    r = rel.replace("\\", "/").lower()
    if any(h in r for h in SERVER_HINTS):
        return False
    return any(r.startswith(h) or ("/" + h) in r for h in FRONTEND_HINTS) or r.endswith((".jsx", ".tsx", ".vue", ".svelte", ".html"))


def walk(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXT and not name.startswith(".env") and name not in ("firestore.rules", "database.rules.json", ".gitignore"):
                continue
            try:
                if os.path.getsize(path) > MAX_BYTES:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    yield path, os.path.relpath(path, root), f.read()
            except OSError:
                continue


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1


def mask(s):
    s = s.strip()
    return s[:6] + "…" + s[-4:] if len(s) > 14 else s[:3] + "…"


def add(findings, fid, sev, title, rel, line, why, fix, evidence=""):
    findings.append({"id": fid, "severity": sev, "title": title, "file": rel, "line": line,
                     "why": why, "fix": fix, "evidence": evidence})


def jwt_role(token):
    import base64
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = json.loads(base64.urlsafe_b64decode(part))
        return payload.get("role")
    except Exception:
        return None


def scan(root):
    findings = []
    files = list(walk(root))
    all_names = {rel.replace("\\", "/") for _, rel, _ in files}
    joined_sql = []
    gitignore = ""
    has_stripe = False
    webhook_files = []
    has_rate_limit = False
    has_supabase = False
    ai_server_calls = []
    pkg_deps = {}

    for path, rel, text in files:
        relp = rel.replace("\\", "/")
        base = os.path.basename(relp)

        if base == ".gitignore":
            gitignore = text

        # .env committed
        if base.startswith(".env") and base not in (".env.example", ".env.sample", ".env.template"):
            real = [l for l in text.splitlines() if "=" in l and not l.strip().startswith("#") and l.split("=", 1)[1].strip() not in ("", '""', "''")]
            if real:
                add(findings, "secret.env_committed", "Critical", ".env file with values is in the project",
                    relp, 1, "Anything in this file is visible to anyone who can see the repo.",
                    "Delete it from the repo, add .env* to .gitignore, and rotate every key it contains.",
                    f"{len(real)} value(s) set")

        # secret patterns
        for fid, sev, title, rx, why, fix in SECRET_PATTERNS:
            for m in re.finditer(rx, text):
                if base.endswith((".md", ".txt")) and fid in ("secret.stripe_test",):
                    continue
                s = sev
                t = title
                if is_frontend(relp) and s != "Critical" and fid != "secret.stripe_test":
                    s = "Critical"
                    t = title + " (browser code)"
                add(findings, fid, s, t, relp, line_of(text, m.start()), why, fix, mask(m.group(0)))

        # Supabase service_role JWT
        for m in JWT_RE.finditer(text):
            if jwt_role(m.group(0)) == "service_role":
                add(findings, "secret.supabase_service_role", "Critical", "Supabase service_role key in code",
                    relp, line_of(text, m.start()),
                    "This key ignores all Row Level Security. Anyone with it can read, change or delete your whole database.",
                    "Rotate it in Supabase (Project Settings, API), use only the anon key in the browser, and keep service_role in server-only env vars.",
                    mask(m.group(0)))

        # secret under public prefix
        envlike = base.startswith(".env") or base.endswith((".yml", ".yaml", ".toml", ".sh")) or base == "Dockerfile"
        for rx in (PUBLIC_PREFIX_SECRET_RES if envlike else PUBLIC_PREFIX_SECRET_RES[1:]):
            for m in rx.finditer(text):
                add(findings, "secret.public_prefix", "Critical", "Secret-sounding variable exposed to the browser",
                    relp, line_of(text, m.start("name")),
                    f"Variables starting with {m.group(2)} are bundled into the website, so anyone can read them.",
                    "Rename it without the public prefix and only read it in server code.", m.group("name"))

        if re.search(r"@supabase/|from supabase import|supabase_flutter|supabase-py|\bsupabase/migrations\b", text) or relp.startswith("supabase/"):
            has_supabase = True
        if base.endswith(".sql"):
            joined_sql.append((relp, text))

        # Firebase open rules
        if base in ("firestore.rules", "storage.rules", "database.rules.json") or base.endswith(".rules"):
            if re.search(r"allow\s+read\s*,\s*write\s*:\s*if\s+true", text) or re.search(r'"\.(read|write)"\s*:\s*true', text):
                add(findings, "db.firebase_open", "Critical", "Firebase rules allow anyone to read and write",
                    relp, 1, "Anyone on the internet can read or wipe this database.",
                    "Replace the rules so users can only read and write their own documents (request.auth.uid == userId).")
            m = re.search(r"request\.time\s*<\s*timestamp\.date\((\d{4}),\s*(\d+),\s*(\d+)\)", text)
            if m:
                add(findings, "db.firebase_test_mode", "Critical", "Firebase still in 'test mode' rules",
                    relp, line_of(text, m.start()), "Test-mode rules leave the database open to everyone until that date.",
                    "Write real per-user rules before launch.")

        # Stripe / payments
        low = text.lower()
        if "stripe" in low:
            has_stripe = True
            if "webhook" in low or "webhook" in relp.lower() or "stripe-signature" in low or "checkout.session.completed" in low:
                webhook_files.append((relp, text))
            m = re.search(r"(unit_amount|amount)\s*:\s*(req\.body|body|request\.json|params|query)\.", text)
            if m:
                add(findings, "pay.client_price", "High", "Payment amount taken from the request",
                    relp, line_of(text, m.start()), "A buyer can change the price to $0.01 before paying.",
                    "Look up the price on the server from a product ID instead of trusting the browser.")

        if re.search(r"rate.?limit|ratelimit|upstash|slowapi|express-rate-limit|throttle", low):
            has_rate_limit = True

        if not is_frontend(relp) and re.search(r"openai|anthropic|generativelanguage|gemini|replicate", low) and base.endswith((".js", ".ts", ".py", ".mjs")):
            ai_server_calls.append(relp)

        # debug in prod
        for m in re.finditer(r"debug\s*[:=]\s*(true|True)|DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True", text):
            if base.endswith((".md", ".txt")):
                continue
            add(findings, "hyg.debug", "Medium", "Debug mode switched on",
                relp, line_of(text, m.start()), "Debug mode can show attackers your code paths, settings and sometimes secrets.",
                "Turn debug off for production or tie it to an environment variable.")
        for m in re.finditer(r"""(origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*)""", text):
            add(findings, "hyg.cors_star", "Medium", "CORS allows every website",
                relp, line_of(text, m.start()), "Any website can call your API from a visitor's browser.",
                "Allow only your own domain(s).")

        if base == "package.json":
            try:
                pkg = json.loads(text)
                for sect in ("dependencies", "devDependencies"):
                    pkg_deps.update(pkg.get(sect, {}) or {})
            except Exception:
                pass

    # Supabase RLS analysis
    if joined_sql:
        created = {}
        rls_on = set()
        for relp, sql in joined_sql:
            for m in re.finditer(r"create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?\"?([a-z0-9_]+)\"?", sql, re.I):
                created.setdefault(m.group(1).lower(), (relp, line_of(sql, m.start())))
            for m in re.finditer(r"alter\s+table\s+(?:only\s+)?(?:public\.)?\"?([a-z0-9_]+)\"?\s+enable\s+row\s+level\s+security", sql, re.I):
                rls_on.add(m.group(1).lower())
            for m in re.finditer(r"create\s+policy[\s\S]{0,300}?using\s*\(\s*true\s*\)", sql, re.I):
                add(findings, "db.rls_permissive", "Critical", "Database policy lets everyone through (USING (true))",
                    relp, line_of(sql, m.start()),
                    "RLS is on, but this rule lets any user read every row, so it does nothing.",
                    "Change the rule to check ownership, e.g. USING (auth.uid() = user_id).")
            for m in re.finditer(r"security\s+definer", sql, re.I):
                add(findings, "db.security_definer", "Medium", "SECURITY DEFINER function (check who can call it)",
                    relp, line_of(sql, m.start()),
                    "These functions run with full rights. If the public can call them, they can bypass your rules.",
                    "Revoke EXECUTE from anon and public unless the function is meant to be public.")
        for table, (relp, line) in created.items():
            if table not in rls_on:
                add(findings, "db.rls_off", "Critical", f"Table '{table}' has no Row Level Security",
                    relp, line,
                    "With RLS off, anyone holding your public Supabase key can read and change every row in this table.",
                    f"Run: ALTER TABLE public.{table} ENABLE ROW LEVEL SECURITY; then add a policy limiting rows to their owner.")
    elif has_supabase:
        add(findings, "db.rls_unknown", "Could not check", "Supabase used but no migration files found",
            "(project)", 0, "We can't see your table rules from the code, so we can't confirm RLS.",
            "In the Supabase dashboard, open Table Editor and confirm no table shows 'RLS disabled'. Or export migrations into the repo for the re-scan.")

    # Stripe webhook verification
    if has_stripe:
        verified = any(re.search(r"constructEvent|construct_event|webhooks\.verify|verifyHeader", t) for _, t in webhook_files)
        if webhook_files and not verified:
            relp = webhook_files[0][0]
            add(findings, "pay.webhook_unverified", "High", "Stripe webhook does not verify the signature",
                relp, 1, "Anyone can send a fake 'payment succeeded' message and unlock paid features for free.",
                "Use stripe.webhooks.constructEvent(rawBody, signatureHeader, webhookSecret) and reject the request if it throws.")
        elif not webhook_files:
            add(findings, "pay.webhook_missing", "Could not check", "Stripe used but no webhook handler found",
                "(project)", 0, "Without a webhook, apps often grant access from the success page, which anyone can visit.",
                "Grant access only after a verified checkout.session.completed webhook.")

    # Rate limiting on AI endpoints
    if ai_server_calls and not has_rate_limit:
        add(findings, "abuse.no_rate_limit", "Medium", "Paid AI API calls with no rate limiting found",
            ai_server_calls[0], 0, "One bot can call this endpoint in a loop and run up your AI bill overnight.",
            "Add per-user rate limits (e.g. Upstash Ratelimit or express-rate-limit) and set a spending cap with your AI provider.")

    # .gitignore
    if not re.search(r"^\.env", gitignore, re.M):
        add(findings, "hyg.gitignore_env", "Medium", ".env files are not in .gitignore",
            ".gitignore" if gitignore else "(project)", 0, "The next time you save keys in .env, they will be committed and published.",
            "Add a line `.env*` and `!.env.example` to .gitignore.")

    # Suspicious deps (cheap slopsquatting heuristic)
    known = {"react", "next", "express", "stripe", "@supabase/supabase-js", "openai", "@anthropic-ai/sdk", "firebase", "axios", "lodash", "zod", "tailwindcss", "vite", "typescript"}
    for dep in pkg_deps:
        for k in known:
            if dep != k and len(dep) >= 4 and _edit1(dep, k):
                add(findings, "dep.lookalike", "High", f"Package '{dep}' looks like a misspelling of '{k}'",
                    "package.json", 0, "Look-alike packages are a known way attackers slip malware into AI-written projects.",
                    f"Confirm '{dep}' is intended. If not, replace it with '{k}'.")

    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Could not check": 4}
    # de-duplicate same id+file+line
    seen, uniq = set(), []
    for f in findings:
        key = (f["id"], f["file"], f["line"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    uniq.sort(key=lambda f: (order.get(f["severity"], 9), f["file"], f["line"]))
    return uniq, len(files)


def _edit1(a, b):
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    s, l = (a, b) if len(a) < len(b) else (b, a)
    for i in range(len(l)):
        if l[:i] + l[i + 1:] == s:
            return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Ship-Ready Scan: find common security mistakes in AI-built apps")
    ap.add_argument("path")
    ap.add_argument("--json", help="write findings to this JSON file")
    ap.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="none",
                    help="exit with code 1 if any finding is at or above this severity (default: none)")
    ap.add_argument("--github", action="store_true",
                    help="GitHub Actions mode: add inline annotations and a job summary")
    a = ap.parse_args()
    if not os.path.isdir(a.path):
        sys.exit(f"Not a folder: {a.path}")
    findings, n = scan(a.path)
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if a.github:
        github_output(findings, n, counts, a.path)
    print(f"Scanned {n} files. " + ", ".join(f"{k}: {v}" for k, v in counts.items()) if findings else f"Scanned {n} files. No findings.")
    for f in findings:
        loc = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        ev = f"  [{f['evidence']}]" if f["evidence"] else ""
        print(f"[{f['severity']}] {f['title']}  ({loc}){ev}")
    print()
    print("This scan checks patterns, not your app's logic. Want a person to review it,")
    print("with plain-English fixes and copy-paste prompts for your coding agent?")
    print("Ship-Ready Check: https://shipreadycheck-dev.github.io")
    if a.json:
        with open(a.json, "w") as out:
            json.dump({"files_scanned": n, "counts": counts, "findings": findings}, out, indent=2)
    rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    limit = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(a.fail_on)
    if limit and any(rank.get(f["severity"], 0) >= limit for f in findings):
        print(f"\nFailing: found issues at or above '{a.fail_on}' severity.")
        sys.exit(1)


def _gh_escape(s, prop=False):
    s = str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if prop:
        s = s.replace(":", "%3A").replace(",", "%2C")
    return s


def github_output(findings, n, counts, root):
    """Inline annotations on the changed files, plus a readable job summary."""
    level = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "notice"}
    prefix = os.path.relpath(os.path.abspath(root), os.getcwd())
    for f in findings:
        kind = level.get(f["severity"], "notice")
        props = [f"title={_gh_escape(f['severity'] + ': ' + f['title'], True)}"]
        if not f["file"].startswith("("):
            path = f["file"] if prefix == "." else os.path.join(prefix, f["file"])
            props.insert(0, f"file={_gh_escape(path, True)}")
            if f["line"]:
                props.insert(1, f"line={f['line']}")
        print(f"::{kind} {','.join(props)}::{_gh_escape(f['why'] + ' Fix: ' + f['fix'])}")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    order = ["Critical", "High", "Medium", "Low", "Could not check"]
    lines = ["## Ship-Ready Scan", ""]
    if not findings:
        lines += [f"Scanned {n} files. **No issues found.**", "",
                  "A clean scan means none of the common patterns were found. It can't prove the app is secure."]
    else:
        lines += [f"Scanned {n} files.", "",
                  "| " + " | ".join(order) + " |", "|" + "---|" * len(order),
                  "| " + " | ".join(str(counts.get(k, 0)) for k in order) + " |", "",
                  "| Severity | Issue | Where | How to fix |", "|---|---|---|---|"]
        for f in findings:
            loc = f"`{f['file']}:{f['line']}`" if f["line"] else f"`{f['file']}`"
            fix = f["fix"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {f['title'].replace('|', '/')} | {loc} | {fix} |")
    lines += ["", "---",
              "Want a person to review what patterns can't see, with plain-English fixes and copy-paste prompts "
              "for your coding agent? [Ship-Ready Check](https://shipreadycheck-dev.github.io)"]
    with open(summary_path, "a") as out:
        out.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
