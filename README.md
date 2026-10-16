# Ship-Ready Scan

**Find the security mistakes AI coding tools make, before you launch.**

Built your app with Lovable, Bolt, Cursor, Claude Code, Replit or v0? This free scanner checks your project for the mistakes behind real leaks: exposed API keys, Supabase tables open to the public, fake-able Stripe payments, and more. It explains each problem in plain English.

- One file, Python 3 only, nothing to install
- Reads your code, never runs it
- Runs entirely on your machine: nothing is uploaded anywhere

## Run it

1. Download your project (on GitHub: **Code**, then **Download ZIP**, then unzip it).
2. Download `shipready_scan.py` from this page.
3. In a terminal, run:

```
python3 shipready_scan.py path/to/your-project
```

Want the results as a file? Add `--json results.json`.

## Run it on every push (GitHub Action)

Catch a leaked key before it ever ships. Create `.github/workflows/ship-ready-scan.yml` in your repo with:

```yaml
name: Ship-Ready Scan
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: shipreadycheck-dev/shipready-scan@v1
```

Or just paste this into your coding agent:

> Add a GitHub Actions workflow at `.github/workflows/ship-ready-scan.yml` that runs on push and pull_request, checks out the code with actions/checkout@v4, and then runs `shipreadycheck-dev/shipready-scan@v1`. Give it `permissions: contents: read`.

Each run adds the problems as comments on the exact lines in your code, and a summary table on the run page. By default the check fails only on **Critical** issues, like a secret key in your code.

| Option | Default | What it does |
|---|---|---|
| `path` | `.` | Folder to scan |
| `fail-on` | `critical` | Fail the check at this severity or worse: `critical`, `high`, `medium`, `low` or `none` |

```yaml
      - uses: shipreadycheck-dev/shipready-scan@v1
        with:
          fail-on: high
```

The action only reads your files. It never runs your code, needs no secrets, and sends nothing anywhere.

**Not comfortable with a terminal?** Paste this into your coding agent (Cursor, Claude Code and so on):

> Download https://raw.githubusercontent.com/shipreadycheck-dev/shipready-scan/main/shipready_scan.py and run it with python3 on this project. Explain each finding to me in plain English. Do not change anything yet.

## What it checks

| Check | Why it matters |
|---|---|
| Secret keys in code (OpenAI, Anthropic, Stripe, AWS, GitHub, Google, private keys) | Anyone who finds them can spend your money |
| Supabase `service_role` key anywhere in the code | It skips every database rule |
| Secrets behind public prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`) | Those variables are copied into your website |
| `.env` files committed, or missing from `.gitignore` | Your keys go public with your repo |
| Database URLs with passwords | Direct access to your whole database |
| Supabase tables without Row Level Security | Anyone with your public key can read them |
| Supabase policies using `USING (true)` | RLS is "on" but lets everyone in |
| `SECURITY DEFINER` functions | Can bypass your rules if the public can call them |
| Firebase rules open to everyone or in test mode | Anyone can read or wipe your data |
| Stripe webhooks that don't verify the signature | Anyone can fake a payment and get your paid plan |
| Prices taken from the browser | Buyers can change the price |
| Paid AI endpoints with no rate limiting | One bot can run up your bill overnight |
| Debug mode on, CORS open to every site | Leaks details, widens your attack surface |
| Look-alike package names (`strpe` for `stripe`) | A known way to slip malware into AI-written projects |

Public keys that are meant to be in your website, like Stripe `pk_` keys and the Supabase **anon** key, are not flagged.

## What it doesn't do

This is a pattern scanner. It finds likely problems; it can't understand your app's logic. A clean result does not mean your app is secure. It can't see settings that live outside your code, like your Supabase dashboard, and it is not a penetration test. Treat every finding as a lead to confirm by reading the code.

## Want a person to check it?

**[Ship-Ready Check](https://shipreadycheck-dev.github.io)** runs this scan plus a manual review of the things patterns can't see (who can read whose data, how payments unlock access, what your agent actually wired up). You get a plain-English report within 24 hours, with copy-paste fix prompts for your coding agent on the Full tier. From $29.

Free: the [10-Minute Pre-Launch Security Checklist](https://shipreadycheck-dev.github.io/#free) and our [security guides](https://shipreadycheck-dev.github.io/guides.html).

## License

MIT. Use it, fork it, add it to your CI.
