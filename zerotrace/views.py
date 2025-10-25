from django.shortcuts import redirect 
from django.http import HttpResponse
from django.template import loader
from .models import users
from .models import forgotpassword
from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import socket, ipaddress
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup
from django.http import HttpResponse, HttpResponseBadRequest
from django.views.decorators.http import require_http_methods
from django.contrib.auth.hashers import check_password
import random
import smtplib








def index(request):
    template=loader.get_template('index.html')
    return HttpResponse(template.render())



def about(request):
    template=loader.get_template('about.html')
    return HttpResponse(template.render())





@ csrf_exempt
def signup(request):
    template=loader.get_template('signup.html')
    # write the singhup logic here..
    if request.method == 'POST':
        username = request.POST.get("username")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        fullname = request.POST.get("fullname")
        password = request.POST.get("password")


        profile=users(username=username,email=email,phone=phone,fullname=fullname,password=make_password(password))
        profile.save()        
        return redirect("login")    
    return HttpResponse(template.render())




@ csrf_exempt
def login(request):
    template=loader.get_template('login.html')
    if request.method=='POST':
        email=request.POST.get("email")
        password=request.POST.get("password")

        try:
            # Get the user with the email
            user_obj = users.objects.get(email=email)
        except users.DoesNotExist:
            user_obj = None


        if user_obj is not None :
            if user_obj and check_password(password,user_obj.password):
                request.session["user_id"] = user_obj.id
                return redirect("dashboard")
            else:
                return HttpResponse("not loged in")
                #messages.error(request, "Invalid password")
        else:
            messages.error(request, "Email not registered")
            return redirect("signup")

    return HttpResponse(template.render())









#main code for scaning
@ csrf_exempt
@require_http_methods(["GET", "POST"])
def scan(request):


    user_id = request.session.get("user_id")

    if not user_id:
        return redirect("login")


    template = loader.get_template('scanner.html')


    # If GET -> show page empty
    if request.method == "GET":
        return HttpResponse(template.render({}, request))

    # --- read & basic validation ---
    target_url = (request.POST.get("url") or "").strip()
    if not target_url:
        return HttpResponseBadRequest("Missing target_url")

    # Basic URL parse check
    try:
        parsed = urlparse(target_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return HttpResponseBadRequest("Only http(s) URLs with a host are allowed.")
    except Exception:
        return HttpResponseBadRequest("Invalid URL")

    # --- Basic SSRF protection: resolve host and block private/loopback/reserved IPs ---
    try:
        hostname = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        addrs = set()
        for ai in socket.getaddrinfo(hostname, port):
            addrs.add(ai[4][0])

        for a in addrs:
            ip = ipaddress.ip_address(a)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return HttpResponseBadRequest("Target resolves to a non-public IP (blocked).")
    except Exception as e:
        return HttpResponseBadRequest(f"Host resolution error: {e}")

    # --- perform polite HTTP fetch (HEAD then GET fallback) ---
    headers = {"User-Agent": "BlackBox-Passive/1.0"}
    try:
        resp = requests.head(target_url, allow_redirects=True, timeout=8, headers=headers)
        # HEAD may be blocked or minimal, fallback to GET to obtain body when needed
        if resp.status_code >= 400 or len(resp.headers) < 3:
            resp = requests.get(target_url, allow_redirects=True, timeout=12, headers=headers)
    except requests.RequestException as e:
        context = {"error": f"Request error: {e}"}
        return HttpResponse(template.render(context, request))

    # --- collect basic scan data ---
    scan_data = {
        "target": target_url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "title": None,
        "robots": None,
        "xss": {},
        "sqli": {},
        "missing_security_headers": [],
        "notes": [],
    }

    # Security headers to check
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
    ]

    # Find missing security headers
    missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
    scan_data["missing_security_headers"] = missing

    # robots.txt (polite)
    try:
        base = f"{parsed.scheme}://{parsed.netloc}"
        robots_url = urljoin(base, "/robots.txt")
        r = requests.get(robots_url, timeout=5, headers=headers)
        if r.status_code == 200:
            scan_data["robots"] = r.text[:3000]
    except Exception:
        scan_data["robots"] = None

    # parse body for form/input/script heuristics
    content_type = resp.headers.get("Content-Type", "")
    body_text = ""
    if ("html" in content_type) or ("text" in content_type) or resp.text:
        body_text = resp.text[:200000]

    soup = None
    try:
        soup = BeautifulSoup(body_text, "html.parser")
    except Exception:
        soup = None

    # XSS passive indicators
    xss_info = {
        "forms_count": 0,
        "forms": [],
        "text_inputs_count": 0,
        "inline_js_count": 0,
        "inline_event_handlers": [],
        "has_csp": bool(resp.headers.get("Content-Security-Policy")),
        "csp": resp.headers.get("Content-Security-Policy"),
        "x_xss_protection": resp.headers.get("X-XSS-Protection"),
    }

    if soup:
        # title
        title_tag = soup.find("title")
        if title_tag and title_tag.string:
            scan_data["title"] = title_tag.string.strip()

        # forms and inputs
        for f in soup.find_all("form"):
            form_info = {"method": (f.get("method") or "GET").upper(), "action": f.get("action") or "", "inputs": []}
            for inp in f.find_all(["input", "textarea", "select"]):
                typ = inp.get("type", "text") if inp.name == "input" else inp.name
                form_info["inputs"].append({
                    "tag": inp.name,
                    "type": typ,
                    "name": inp.get("name"),
                    "id": inp.get("id"),
                    "placeholder": inp.get("placeholder"),
                    "required": bool(inp.get("required"))
                })
                if typ in ("text", "search", "email", "url", "tel"):
                    xss_info["text_inputs_count"] += 1
            xss_info["forms_count"] += 1
            xss_info["forms"].append(form_info)

        # inline script content
        scripts = soup.find_all("script")
        for s in scripts:
            if s.string and s.string.strip():
                xss_info["inline_js_count"] += 1

        # inline event attributes
        found_attrs = set()
        for tag in soup.find_all(True):
            for attr in tag.attrs.keys():
                if attr.lower().startswith("on"):
                    found_attrs.add(attr.lower())
        xss_info["inline_event_handlers"] = sorted(found_attrs)

    scan_data["xss"] = xss_info

    # SQLi passive checks - search page for common SQL error signatures
    SQL_SIGS = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "mysql_fetch",
        "syntax error",
        "sqlstate[",
        "pg_query():",
        "oracle error",
        "ora-",
        "quoted string not properly terminated",
    ]
    found_sigs = []
    low_body = (body_text or "").lower()
    for sig in SQL_SIGS:
        if sig in low_body:
            found_sigs.append(sig)
    scan_data["sqli"]["signatures_found"] = found_sigs

    # Notes / guidance
    if not xss_info["has_csp"]:
        scan_data["notes"].append("No Content-Security-Policy header — adding CSP reduces XSS risk.")
    if xss_info["inline_event_handlers"]:
        scan_data["notes"].append("Inline event-handler attributes detected — review for unsafe DOM usage.")
    if found_sigs:
        scan_data["notes"].append("SQL-like error strings found in page — may indicate error leakage or unsanitized inputs.")
    if scan_data["headers"].get("Server"):
        scan_data["notes"].append("Server header present — may reveal server software/version.")

    # --- Build 'found' and 'not_found' lists for templating (right = found, left = not_found/passed) ---
    found = []
    not_found = []

    # security headers
    for h in SECURITY_HEADERS:
        if h in scan_data["missing_security_headers"]:
            found.append({
                "id": f"hdr-{h}",
                "title": f"{h} missing",
                "desc": f"{h} header is not present — security risk.",
                "severity": "HIGH" if h in ("Content-Security-Policy", "Strict-Transport-Security") else "MED"
            })
        else:
            not_found.append({"id": f"hdr-{h}", "title": f"{h} present", "desc": f"{h} header present."})

    # XSS heuristics
    if xss_info["inline_js_count"] > 0:
        found.append({
            "id": "xss-inline-js",
            "title": "Inline <script> content",
            "desc": f"{xss_info['inline_js_count']} inline script tag(s) with content were found.",
            "severity": "MED"
        })
    else:
        not_found.append({"id": "xss-inline-js", "title": "No inline scripts", "desc": "No inline script tags detected."})

    if xss_info["inline_event_handlers"]:
        found.append({
            "id": "xss-event-handlers",
            "title": "Inline event-handler attributes",
            "desc": "Found event handler attributes: " + ", ".join(xss_info["inline_event_handlers"]),
            "severity": "MED"
        })
    else:
        not_found.append({"id": "xss-event-handlers", "title": "No inline event handlers", "desc": "No onclick/onload/etc attributes detected."})

    # Inputs info (informational)
    not_found.append({"id": "inputs", "title": f"{xss_info['text_inputs_count']} text inputs detected", "desc": "Review server-side handling of these inputs."})

    # SQLi passive detection
    if found_sigs:
        for sig in found_sigs:
            found.append({
                "id": f"sqli-{abs(hash(sig))}",
                "title": "SQL error signature in page",
                "desc": sig,
                "severity": "HIGH"
            })
    else:
        not_found.append({"id": "sqli-none", "title": "No SQL error signatures", "desc": "No common SQL error strings were found."})

    # Server header
    srv = scan_data["headers"].get("Server")
    if srv:
        found.append({"id": "server-header", "title": "Server header reveals info", "desc": f"Server header: {srv}", "severity": "LOW"})
    else:
        not_found.append({"id": "server-header", "title": "Server header not present", "desc": ""})

    # Title & robots
    if scan_data.get("title"):
        not_found.append({"id": "title", "title": "Page title", "desc": scan_data.get("title")})
    if scan_data.get("robots"):
        not_found.append({"id": "robots", "title": "robots.txt present", "desc": (scan_data.get("robots")[:200] + ('...' if len(scan_data.get("robots"))>200 else ''))})

    context = {
        "target": target_url,
        "scan_status_code": scan_data.get("status_code"),
        "found": found,
        "not_found": not_found,
        "notes": scan_data.get("notes", []),
        "raw_headers": scan_data.get("headers", {}),
        "scan_data": scan_data,
    }

    # render the template with results (your scanner.html should read 'found' and 'not_found')
    return HttpResponse(template.render(context, request))



#scanning code over











def dashboard(request):
    template = loader.get_template('dashboard.html')

    # Get user_id from session
    user_id = request.session.get("user_id")

    if not user_id:
        # No session → force login
        return redirect("login")

    try:
        current_user = users.objects.get(id=user_id)
    except users.DoesNotExist:
        # Invalid session, clear it
        request.session.flush()
        return redirect("login")

    context = {
        'username': current_user.username,
        'fullname': current_user.fullname,
        'email': current_user.email,
    }
    return HttpResponse(template.render(context, request))





@csrf_exempt
def delete(request):
    template=loader.get_template("signup.html")
    user_id=request.session.get("user_id")
    if not user_id:
        return redirect("login")
    current_user=users.objects.get(id=user_id)
    current_user.delete()
    request.session.flush()
    return HttpResponse(template.render())




@csrf_exempt
def changepassword(request):
    template=loader.get_template("changepassword.html")
    curr_id=request.session.get("user_id")
    if not curr_id:
        # No session → force login
        return redirect("login")

    curr_user=users.objects.get(id=curr_id)

    if request.method=="POST":
        currpassword=request.POST.get("currentpassword")
        newpassword=request.POST.get("newpassword")
        if curr_id and check_password(currpassword,curr_user.password):
            curr_user.password=make_password(newpassword)
            curr_user.save()
            return redirect("dashboard")
        else:
            return redirect("changepassword")
    return HttpResponse(template.render())





def logout(request):
    request.session.flush()
    return redirect("login")





@csrf_exempt
def forgotpasswords(request):
    template=loader.get_template("forgotpassword.html")
    if request.method=="POST":
        email=request.POST.get("email")
        try:
            # Get the user with the email
            user_obj = users.objects.get(email=email)
        except users.DoesNotExist:
            user_obj = None
            return HttpResponse("no found")
        otp=random.randint(10000, 99999)
        if user_obj is not None:
            profile=forgotpassword(email=email,otp=str(otp))
            profile.save()
            #write teh emailing logic here ----!
            
            
            s = smtplib.SMTP('smtp.gmail.com', 587)
            s.starttls()
            s.login("mannvats29@gmail.com", "hxnc jlpn fmgw hdcx")
            s.sendmail("mannvats29@gmail.com", email,str(otp))
            s.quit()
            request.session["user_email"]=email
            return redirect("newpassword")
        
    return HttpResponse(template.render())



@csrf_exempt
def newpassword(request):
    template=loader.get_template("newpassword.html")
    curr_email=request.session.get("user_email")
    #write the passwrod changing and teh apssworf and configuring the otp logiuc here ----!dont forgot ot delete the account and flush teh seeison after compliting the password change
    if request.method =="POST":
        otp=request.POST.get("otp")
        password=request.POST.get("password")
        
        try:
            curr_user=forgotpassword.objects.get(email=curr_email)
        except:
            curr_user=None
            return HttpResponse("session not created!")

        if curr_user and (str(otp)==curr_user.otp):#we cant use the check_password funtion here as it first convbert the given otp into the hasses to the otp stored in the data base which in the plain text so ::::
            curr_user=users.objects.get(email=curr_email)
            curr_user.password=make_password(password)
            curr_user.save()
            curr_user=forgotpassword.objects.get(email=curr_email)
            curr_user.delete()
            request.session.flush()
            return redirect("login")

    return HttpResponse(template.render())















