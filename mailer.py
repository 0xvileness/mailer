import re
import requests
import dns.resolver
import hashlib
import logging
import threading
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# 1. Welcome Logo and Description -----------------------------------------------

def print_welcome():
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

    logo = f"""{BLUE}
 ███▄ ▄███▓ ▄▄▄       ██▓ ██▓    ▓█████  ██▀███     
▓██▒▀█▀ ██▒▒████▄    ▓██▒▓██▒    ▓█   ▀ ▓██ ▒ ██▒   
▓██    ▓██░▒██  ▀█▄  ▒██▒▒██░    ▒███   ▓██ ░▄█ ▒   
▒██    ▒██ ░██▄▄▄▄██ ░██░▒██░    ▒▓█  ▄ ▒██▀▀█▄     
▒██▒   ░██▒ ▓█   ▓██▒░██░░██████▒░▒████▒░██▓ ▒██▒   
░ ▒░   ░  ░ ▒▒   ▓▒█░░▓  ░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░   
░  ░      ░  ▒   ▒▒ ░ ▒ ░░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░   
░      ░     ░   ▒    ▒ ░  ░ ░      ░     ░░   ░    
       ░         ░  ░ ░      ░  ░   ░  ░   ░  {RESET}"""     
                                                    

    print(logo)
    print()  # Gap space added here between logo and description

    description = f"{WHITE} Powerful OSINT tool to validate and investigate email addresses across social platforms and data breaches.{RESET}"
    print(description)
    print()  # Blank line after description before the prompt

# 2. Logging Setup -------------------------------------------------------------

logging.basicConfig(
    filename='osint_tool.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s: %(message)s',
    level=logging.INFO
)

# 3. Core Utility Functions ----------------------------------------------------

def validate_email_syntax(email):
    pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
    valid = re.match(pattern, email) is not None
    logging.info(f"Syntax validation for {email}: {valid}")
    return valid

def has_mx_record(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        has_mx = bool(records)
        logging.info(f"MX record check for {domain}: {has_mx}")
        return has_mx
    except Exception as e:
        logging.error(f"MX record check failed for {domain}: {e}")
        return False

def is_disposable(email):
    disposable_domains = [
        'mailinator.com', '10minutemail.com', 'guerrillamail.com', 'throwawaymail.com',
        'tempmail.com', 'yopmail.com', 'fakeinbox.com'
    ]
    domain = email.split('@')[1].lower()
    disposable = domain in disposable_domains
    logging.info(f"Disposable email check for {email}: {disposable}")
    return disposable

def gravatar_profile(email):
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/{email_hash}.json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            logging.info(f"Gravatar profile found for {email}")
            return response.json()
        logging.info(f"No Gravatar profile for {email}")
    except Exception as e:
        logging.error(f"Gravatar request failed for {email}: {e}")
    return None

def github_search(email):
    url = f"https://api.github.com/search/users?q={email}+in:email"
    headers = {'Accept': 'application/vnd.github.v3+json'}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.ok:
            data = response.json()
            users = data.get("items", [])
            logging.info(f"GitHub search results for {email}: {len(users)} users found")
            return users
    except Exception as e:
        logging.error(f"GitHub search failed for {email}: {e}")
    return []

def hibp_breach(email):
    headers = {"User-Agent": "OSINTTool"}
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            logging.info(f"Breach found for {email}")
            return True
        if response.status_code == 404:
            logging.info(f"No breach found for {email}")
            return False
        else:
            logging.warning(f"HIBP unexpected status for {email}: {response.status_code}")
    except Exception as e:
        logging.error(f"HIBP check failed for {email}: {e}")
    return False

def google_dorking(email):
    dorks = {
        "Exact Email": f'"{email}"',
        "Email User Name": email.split('@')[0],
        "Email Domain": email.split('@')[1],
        "Email in URLs": f'inurl:{email}',
        "Email in Text": f'intext:"{email}"',
        "Email on Social Sites": f'site:linkedin.com OR site:facebook.com OR site:twitter.com "{email}"',
    }
    base_url = "https://www.google.com/search?q="
    results = {name: base_url + requests.utils.quote(query) for name, query in dorks.items()}
    logging.info(f"Google dork URLs generated for {email}")
    return results

def social_media_search(email):
    username = email.split('@')[0]
    domain = email.split('@')[1]
    results = {
        "Twitter Search": f"https://twitter.com/search?q={email}",
        "Instagram Profile": f"https://www.instagram.com/{username}/",
        "LinkedIn Search": f"https://www.linkedin.com/search/results/all/?keywords={email}",
        "Facebook Search": f"https://www.facebook.com/search/top?q={email}"
    }
    logging.info(f"Social media search URLs created for {email}")
    return results

def email_reputation(email):
    blacklist = ['spamdomain.com', 'blacklisted.com']
    domain = email.split('@')[1]
    reputation = "Blacklisted" if domain in blacklist else "Clean"
    logging.info(f"Email reputation check for {email}: {reputation}")
    return reputation

def generate_pdf_report(email, data_summary, filename="report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    margin = 40
    y = height - margin

    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, y, f"OSINT Report for {email}")
    y -= 30

    c.setFont("Helvetica", 12)
    for section, content in data_summary.items():
        if isinstance(content, list):
            c.drawString(margin, y, f"{section}:")
            y -= 18
            for item in content:
                line = str(item)
                c.drawString(margin+20, y, line[:90])
                y -= 14
                if y < margin:
                    c.showPage()
                    y = height - margin
        else:
            c.drawString(margin, y, f"{section}: {content}")
            y -= 20
            if y < margin:
                c.showPage()
                y = height - margin

    c.save()
    logging.info(f"PDF report generated: {filename}")

def worker(email, results, lock):
    platform_results = {
        'Gravatar': gravatar_profile(email) is not None,
        'GitHub': [user.get("login") for user in github_search(email)] or [],
        'HaveIBeenPwned': hibp_breach(email),
        'Email Reputation': email_reputation(email),
        'Social Media URLs': social_media_search(email)
    }
    # Add Medium and Telegram profiles to social URLs
    username = email.split('@')[0]
    medium_url = f"https://medium.com/@{username}"
    telegram_url = f"https://t.me/{username}"
    platform_results["Social Media URLs"].update({
        "Medium Profile": medium_url,
        "Telegram Profile": telegram_url
    })
    with lock:
        results.update(platform_results)

# 4. Main Program --------------------------------------------------------------

def main():
    print_welcome()
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    user_email = input(f"{BLUE}Enter an email address: {RESET}").strip()

    logging.info(f"Starting OSINT for email: {user_email}")
    print(f"Validating {user_email}...")

    if not validate_email_syntax(user_email):
        print("Invalid email syntax.")
        return

    domain = user_email.split("@")[1]
    if not has_mx_record(domain):
        print("Domain has no valid MX records.")
        return

    if is_disposable(user_email):
        print("Disposable email detected.")
    else:
        print("Email appears non-disposable.")

    results = {}
    lock = threading.Lock()
    t = threading.Thread(target=worker, args=(user_email, results, lock))
    t.start()
    t.join()

    google_links = google_dorking(user_email)

    # --- OSINT Results --- heading bold blue with gap line after
    print(f"\n{BOLD}{BLUE}--- OSINT Results ---{RESET}\n")

    def status_color(val):
        if isinstance(val, bool):
            return GREEN + "True" + RESET if val else RED + "False" + RESET
        if isinstance(val, list):
            return GREEN + str(val) + RESET if val else RED + str(val) + RESET
        return GREEN + str(val) + RESET if val else RED + str(val) + RESET

    print(f"{BLUE}Gravatar Found:{RESET} {status_color(results.get('Gravatar', False))}")
    print(f"{BLUE}GitHub Users Found:{RESET} {status_color(results.get('GitHub', []))}")
    print(f"{BLUE}Data Breach Found:{RESET} {status_color(results.get('HaveIBeenPwned', False))}")
    # Reputation: green if Clean, red otherwise
    reputation = results.get('Email Reputation', '')
    rep_color = GREEN if reputation.lower() == 'clean' else RED
    print(f"{BLUE}Email Reputation:{RESET} {rep_color}{reputation}{RESET}")

    print()  # gap before social media URLs

    # Social Media Search URLs bold blue + gap line after
    print(f"{BOLD}{BLUE}Social Media Search URLs:{RESET}\n")

    social = results.get('Social Media URLs', {})

    # Print social media labels blue, URLs white
    platforms_order = [
        "Twitter Search",
        "Instagram Profile",
        "LinkedIn Search",
        "Facebook Search",
        "Medium Profile",
        "Telegram Profile"
    ]
    for platform in platforms_order:
        url = social.get(platform, None)
        if url:
            print(f"{BLUE}{platform}:{RESET} {WHITE}{url}{RESET}")

    print()  # gap before Google Dork Suggestions

    # Google Dork Suggestions bold blue + gap line after
    print(f"{BOLD}{BLUE}Google Dork Suggestions:{RESET}\n")

    keys_order = [
        "Exact Email",
        "Email User Name",
        "Email Domain",
        "Email in URLs",
        "Email in Text",
        "Email on Social Sites"
    ]
    for key in keys_order:
        url = google_links.get(key, "")
        print(f"{BLUE}{key}:{RESET} {WHITE}{url}{RESET}")

    print()  # gap before reports saved

    csv_filename = f"osint_report_{user_email.replace('@', '_at_')}.csv"
    pdf_filename = f"osint_report_{user_email.replace('@', '_at_')}.pdf"

    print(f"{WHITE}CSV report saved as {BLUE}{csv_filename}{RESET}")
    print(f"{WHITE}PDF report saved as {BLUE}{pdf_filename}{RESET}")

    # Save reports
    data_summary = {
        "Email": user_email,
        "Disposable": "Yes" if is_disposable(user_email) else "No",
        "Gravatar Found": results.get('Gravatar'),
        "GitHub Users": ", ".join(results.get('GitHub', [])) or "None",
        "Data Breach Found": "Yes" if results.get('HaveIBeenPwned') else "No",
        "Email Reputation": reputation,
        "Social Media URLs": "\n".join(f"{k}: {v}" for k, v in social.items()),
        "Google Dork URLs": "\n".join(f"{k}: {v}" for k, v in google_links.items())
    }

    pd.DataFrame([data_summary]).to_csv(csv_filename, index=False)
    generate_pdf_report(user_email, data_summary, pdf_filename)


if __name__ == "__main__":
    main()
