# WebVuln Scanner (Django)

A Django web application that takes a target URL from the user and
performs **passive, non-intrusive analysis** of the site's HTML to flag
common indicators of XSS and SQLi risk — without sending any actual
attack payloads to the target.

## What it does

You submit a URL through the web form. The app fetches that page's HTML
once, parses it, and looks for **structural warning signs** in the
document itself — not by injecting anything, just by reading what's
already there:

- **Reflected-parameter indicators** — query parameters from the URL that
  appear echoed back verbatim in the page body (a classic pre-condition
  for reflected XSS, without actually testing an XSS payload)
- **Form analysis** — forms missing CSRF tokens, forms using `GET` for
  data-modifying actions, and input fields with no visible client-side
  validation attributes
- **Unescaped output patterns** — places where user-controllable values
  appear to be inserted into HTML without apparent encoding
- **SQL-adjacent parameter naming** — query/form parameters named things
  like `id`, `user`, `search`, `query` that are common SQLi entry points,
  flagged for manual review rather than tested directly
- **Missing security headers** — checks response headers for the absence
  of `Content-Security-Policy`, `X-Content-Type-Options`,
  `X-Frame-Options`, etc.
- **Basic input sanitization signals** — whether form inputs declare
  `maxlength`, `pattern`, or `type` constraints that suggest (or fail to
  suggest) server-side validation is backed by client-side hints

This is a **triage tool**, not a penetration-testing tool. It tells you
"here's where to look closer," not "this is definitely exploitable." No
payloads are sent, no forms are submitted, no injection is attempted —
every check runs against a single passive GET request to the page you
provide.

## ⚠️ Usage notice

Only scan websites you own or have explicit permission to test. Even
though this tool is passive (a single normal page load, nothing more),
running any kind of automated scanner against a site without authorization
may still violate its terms of service or local law. This tool does not
perform any exploitation — it flags patterns for manual human review.

## Tech stack

- **Backend:** Django
- **HTML parsing:** BeautifulSoup4
- **HTTP requests:** `requests`
- **Frontend:** Django templates (+ optionally your CSS framework of choice)

## Features

- 🔗 Simple web form — paste a URL, get a report
- 🧾 Human-readable results page grouping findings by category
  (Reflected Params / Forms / Headers / Sanitization Signals)
- 🎯 Severity tagging per finding (informational / low / medium) based on
  how many risk indicators stack on the same parameter or form
- 🕓 Scan history — past scans are stored per user session/account so you
  can revisit earlier results
- 📤 Export a scan result as a downloadable report

## Project structure

```
webvuln_scanner/
├── manage.py
├── webvuln_scanner/          # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── scanner/                   # Main app
│   ├── models.py               # ScanResult, Finding models
│   ├── views.py                 # form handling + scan trigger
│   ├── forms.py                  # URL input form
│   ├── analyzer.py                # core passive-analysis logic
│   ├── urls.py
│   └── templates/scanner/
│       ├── home.html
│       └── results.html
├── requirements.txt
└── README.md
```

## Installation

```bash
git clone <your-repo-url>
cd webvuln_scanner

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

python manage.py migrate
python manage.py runserver
```

Then open `http://127.0.0.1:8000` in your browser.

## Usage

1. Open the home page
2. Paste the URL you want to check (must be a site you're authorized to test)
3. Submit — the app fetches the page once and runs the passive checks
4. Review the results page, grouped by category, with severity tags
5. Optionally export the report

## Roadmap

- [ ] Multi-page crawl within the same domain (still passive-only)
- [ ] Cookie/session security attribute checks (`HttpOnly`, `Secure`,
      `SameSite`)
- [ ] Downloadable PDF report
- [ ] Basic rate-limiting / scan-history quota per user

## Disclaimer

This tool is built for educational purposes and authorized security
assessment only. It performs no active exploitation — findings represent
pattern-based indicators that require manual verification, not confirmed
vulnerabilities. The author(s) are not responsible for misuse.

## License

MIT
