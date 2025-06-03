from bs4 import BeautifulSoup
import requests
import tkinter as tk
from tkinter import messagebox, scrolledtext
import logging
import re
from urllib.parse import urlparse, urljoin
import unicodedata
import string
from datetime import datetime
import webbrowser
from collections import defaultdict
# Constants and templates omitted here for brevity (assumed included above)
# --- User-Facing Messages & Examples ---
ROBOTS_TXT_DISALLOWED_MSG = (
    "robots.txt disallows scraping or access is blocked."
)
FREQUENCY_PATTERN = re.compile(r"(?:up to|no more than|not exceed|maximum of)?\s*(\d+)\s*(?:messages?|texts?)?\s*(?:per|/)\s*(day|week|month)",
    re.IGNORECASE)

COMPLIANT_EXAMPLE = """

By [action needed to gain consent – e.g., checking a box, verbally agreeing, signing a form, etc.]
you consent to receive SMS messages from [Brand Name] for [TYPE OF MESSAGES BEING SENT]
Message frequency may vary but will not exceed [Enter Estimated/Expected Message Count Per Day] per day
unless triggered by a notification event. Msg. & Data Rates may apply. Reply HELP for help
Reply STOP to opt out. We will never share your mobile information with third parties or affiliates
for marketing or promotional purposes at any time."""

VERBAL_NOTICE = """

NOTE: Verbal consent methods require a transcript and call recording to be considered compliant.
By verbally agreeing, you consent to receive SMS messages from [Brand Name] for [TYPE OF INFORMATION].
Message frequency may vary but will not exceed [Enter Estimated/Expected Message Count Per Day] per day unless triggered by a notification event.
Msg. & Data Rates may apply. Reply HELP for help. Reply STOP to opt out.
We will never share your mobile information with third parties or affiliates for marketing or promotional purposes at any time."""

PAPER_NOTICE = """

NOTE: In-person paper form consent requires a signed physical document to be considered compliant.
By signing this form you are/checking the box on this paper form. You consent to receive SMS messages from [Brand Name] for [TYPE OF INFORMATION].
Message frequency may vary but will not exceed [Enter Estimated/Expected Message Count Per Day] per day unless triggered by a notification event.
Msg. & Data Rates may apply. Reply HELP for help. Reply STOP to opt out."
We will never share your mobile information with third parties or affiliates for marketing or promotional purposes at any time."""

WEBFORM_NOTICE = """
By checking this checkbox you consent to receive SMS messages from [Brand Name] for [TYPE OF INFORMATION]. 
Message frequency may vary but will not exceed [Enter Estimated/Expected Message Count Per Day] per day unless 
triggered by a notification event. Msg. & Data Rates may apply. Reply HELP for help. Reply STOP to opt out.
We will never share your mobile information with third parties or affiliates for marketing or promotional purposes at any time. 
Link to our Privacy Policy and Terms and Conditions can be found here REPLACE WITH FULL URL OF PRIVACY POLICY AND OR TERMS AND CONDITIONS"""

KEYWORD_NOTICE = """

NOTE: Keyword-based consent must be explicitly described in the privacy policy.
By texting START to (TELEPHONE NUMBER), you consent to receive SMS messages from [Brand Name] for [TYPE OF INFORMATION].
Message frequency may vary but will not exceed [Enter Estimated/Expected Message Count Per Day] per day unless triggered by a notification event.
Msg. & Data Rates may apply. Reply HELP for help. Reply STOP to opt out.
We will never share your mobile information with third parties or affiliates for marketing or promotional purposes at any time."""

NOTICE_MAP = {
    'verbal': VERBAL_NOTICE,
    'paper': PAPER_NOTICE,
    'in person': PAPER_NOTICE,
    'keyword': KEYWORD_NOTICE,
    'webform': WEBFORM_NOTICE
}
# --- Script Behavior Settings ---
MAX_PAGES_TO_CRAWL = 30  # Limit crawl depth
CRAWL_DELAY = 0.5       # Seconds to wait between page requests
FUZZY_THRESHOLD = 80   # Minimum score (0-100) for fuzzy match

# Map canonical method name to the core word(s) to search for fuzzily.
# Using tuples allows for multi-word matching in the helper function.
FUZZY_KEYWORD_MAP = {
    'sms': ('sms',),
    'opt in': ('opt', 'in'),
    'opt out': ('opt', 'out'),
}
TEMPLATE_MATCH_KEYWORDS = [
    'one-to-one', 'msg.', 'stop', 'help', 'consent','keyword', 'opt-in', 
    'opt-out', 'privacy', 'policy', 'terms','TCPA', 'CTIA', 'FCC', 'dnc', 
    'frequency', 'disclosure', 'recordkeeping','signature', 'mobile',
    'data', 'sharing', 'recorded', 'text message'
]

FUZZY_METHOD_KEYWORDS = {
    'verbal': ['verbal'],
    'paper': ['paper', 'sign'],
    'webform': ['webform', 'checkbox'],
    'keyword': ['start', 'sms'],
    'in person': ['in person']
}

# Keywords to identify Privacy Policy links (more variations)
PRIVACY_KEYWORDS = ['privacy', 'policy', 'policies', 'sms policy', 'disclosure']
PRIVACY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PRIVACY_KEYWORDS]

# Keywords to identify Terms links (more variations)
TERMS_KEYWORDS = ['terms', 'conditions', 'user agreement','terms of service', 
    'terms of use','One-to-One Consent', 'Explicit Consent']
TERMS_PATTERNS = [re.compile(p, re.IGNORECASE) for p in TERMS_KEYWORDS]

# Keywords to potentially exclude false positive policy links
EXCLUDE_POLICY_KEYWORDS = ['login', 'careers', 'jobs', 'extension', 'plugin',
    'support', 'cookie', 'accessibility']
EXCLUDE_POLICY_PATTERNS = [re.compile(p, re.IGNORECASE) for p in EXCLUDE_POLICY_KEYWORDS]

# List of keywords that indicate SMS-related context
SMS_KEYWORDS = ['sms', 'text message', 'opt-in', 'opt out', 'opt-in',
'stop', 'help', 'msg', 'one-to-one', 'reply stop', 'reply help'
]
SMS_PATTERNS = [re.compile(re.escape(p), re.IGNORECASE) for p in SMS_KEYWORDS]

PHONE_FIELD_KEYWORDS = ['phone', 'mobile', 'telephone', 'cell', 'contact', 'number', 'tel', 'check box']
PHONE_FIELD_PATTERNS = [re.compile(p, re.IGNORECASE) for p in PHONE_FIELD_KEYWORDS]

DISCLOSURE_KEYWORDS = [
    r'message frequency', r'msg & data rates', r'reply stop', r'reply help',
    r'mobile information.*shared']
DISCLOSURE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in DISCLOSURE_KEYWORDS]

KB_LINKS = {
    "Unite": "https://support.intermedia.com/app/articles/detail/a_id/16843",
    "Elevate": "https://support.serverdata.net/app/articles/detail/a_id/16843",
    "Ascend": "https://support.ascendcloud.com/app/articles/detail/a_id/16843",
}
def check_robots_txt_allows(base_url: str) -> bool:
    try:
        parsed_url = urlparse(base_url)
        robots_url = urljoin(base_url, "/robots.txt")
        headers = {'User-Agent': '*'}
        resp = requests.get(robots_url, timeout=5, headers=headers)
        if resp.status_code == 200:
            lines = resp.text.splitlines()
            ua_match = False
            for line in lines:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                lower = stripped.lower()
                if lower.startswith("user-agent:"):
                    ua_match = (lower == "user-agent:*")
                elif lower.startswith("user-agent:") and ua_match:
                    ua_match = False
                elif ua_match and lower.startswith("disallow:"):
                    rule = lower.split(":", 1)[1].strip()
                    if rule == "/" or rule == "/*":
                        return False
            return True
        return True
    except Exception:
        return True
def extract_primary_domain(url: str) -> str:
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return ""

        parts = hostname.split('.')
        if len(parts) >= 2:
            return ".".join(parts[-2:])  # e.g., 'example.com'
        return hostname  # localhost or bare IP
    except:
        return ""
def normalize_text(text: str) -> str:
    text = unicodedata.normalize('NFKD', text)
    text = text.encode('ascii', 'ignore').decode('utf-8')  # Remove accents
    text = text.lower().strip()
    text = re.sub(f'[{re.escape(string.punctuation)}]', '', text)  # Remove punctuation
    return re.sub(r'\s+', ' ', text)

# --- Utility Functions ---
def validate_and_normalize_url(url: str) -> tuple[bool, str]:
    if not isinstance(url, str):
        return False, url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False, url
        if not parsed.netloc:
            return False, url
        if "." not in parsed.hostname and not parsed.hostname.replace('.', '').isdigit() and parsed.hostname != "localhost":
            return False, url
        return True, url
    except Exception:
        return False, url
from collections import defaultdict



def scrape(self):
    url_input = self.url_entry.get().strip()
    self.result_box.delete(1.0, tk.END)

    # Validate and normalize URL
    is_valid, url = validate_and_normalize_url(url_input)
    if not is_valid:
        messagebox.showerror("Invalid URL", "The URL entered is not valid.\nPlease enter a proper website address (e.g., https://example.com).")
        self.result_box.insert(tk.END, "❌ Invalid URL format.\nPlease use a full URL like https://example.com\n")
        return

    crawl_depth = int(self.depth_var.get())

    # Check robots.txt restrictions
    if not check_robots_txt_allows(url):
        self.result_box.insert(tk.END, f"{ROBOTS_TXT_DISALLOWED_MSG}\n")
        return

    self.root.update_idletasks()

    # Attempt crawl
    try:
        crawl_results = self.crawl_entire_site(url, max_pages=crawl_depth, delay=CRAWL_DELAY)
        if not crawl_results:
            self.result_box.insert(tk.END, f"❌ Unable to retrieve pages from {url}\n")
            return

        summary = self.summarize_crawl_results(crawl_results)
    except Exception as e:
        logging.error(f"Crawl failed: {e}")
        messagebox.showerror("Error", f"An error occurred while crawling the site.\nDetails: {e}")
        self.result_box.insert(tk.END, f"❌ Crawl failed. Error: {e}\n")
        return

    # Display results
    self.result_box.insert(tk.END, summary)
    self.make_links_clickable()

def download_document_content(url: str) -> str:
    try:
        headers = {'User-Agent': 'ComplianceBot/1.5'}
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        if 'html' in content_type or 'text' in content_type or not content_type:
            if int(response.headers.get('Content-Length', '0')) > 2_000_000:
                return ""
            try:
                return response.content.decode(response.apparent_encoding)
            except:
                return response.content.decode('utf-8', errors='ignore')
        return ""
    except:
        return ""

def find_policy_links(html, base_url):
    soup = BeautifulSoup(html, 'html.parser')
    footer = soup.find('footer')
    if not footer:
        possible_footers = soup.find_all(lambda tag: tag.name == 'div' and 'footer' in (tag.get('id', '') + str(tag.get('class', ''))).lower())
        footer = possible_footers[0] if possible_footers else None
    search_scope = footer if footer else soup
    links = search_scope.find_all('a', href=True)
    results = {}
    for link in links:
        text = link.get_text(strip=True).lower()
        href = urljoin(base_url, link['href'])
        if any(p.search(text) or p.search(href) for p in PRIVACY_PATTERNS):
            results['Privacy Policy'] = href
        elif any(p.search(text) or p.search(href) for p in TERMS_PATTERNS):
            results['Terms and Conditions'] = href
    return results

def extract_contact_info(soup: BeautifulSoup) -> tuple[set[str], set[str]]:
    """
    Extracts email addresses and phone numbers from BeautifulSoup object.
    Uses slightly improved regex patterns.
    """
    emails = set()
    phones = set()
    try:
        raw_text = soup.get_text(separator='\n', strip=True)

        # Extract emails from raw text (preserve symbols like "@")
        email_pattern = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        emails = set(email_pattern.findall(raw_text))

        # Normalize text for phone extraction only
        text = normalize_text(raw_text)

        # Regex for North American-like phone numbers (more specific)
        # Allows optional country code, area code in parens or not, separators like space, dot, dash
        phone_pattern = re.compile(
            r"(?:\+?1[\s.-]?)?"  # Optional +1 country code
            r"\(?(\d{3})\)?[\s.-]?"  # Area code (optional parens)
            r"(\d{3})[\s.-]?"  # Prefix
            r"(\d{4})"  # Line number
        )
        # Find all matches and reformat them consistently to 11-digit DID format
        for match in phone_pattern.finditer(text):
            # Format: 1XXXXXXXXXX
            did_number = f"1{match.group(1)}{match.group(2)}{match.group(3)}"
            phones.add(did_number)

    except Exception as e:
        logging.error(f"Error extracting contact info: {e}")

    return emails, phones
def extract_form_fields(soup: BeautifulSoup) -> list[dict]:
    fields = []
    for form in soup.find_all("form"):
        for input_tag in form.find_all(["input", "select", "textarea"]):
            field = {
                "name": input_tag.get("name", "[no name]"),
                "type": input_tag.get("type", "text").lower(),
                "required": input_tag.has_attr("required"),
                "sms_consent": any(keyword in input_tag.get("name", "").lower() for keyword in ["sms", "text", "optin", "opt-in"])
            }
            fields.append(field)
    return fields


def check_compliance_features(content: str) -> tuple[list[str], bool]:
    findings = []
    frequency_matches = FREQUENCY_PATTERN.findall(content)
    has_frequency_estimate = bool(frequency_matches)

    for pattern in DISCLOSURE_PATTERNS + SMS_PATTERNS:
        if pattern.search(content):
            findings.append(pattern.pattern)

    if has_frequency_estimate:
        formatted = [f"{n} per {unit}" for (n, unit) in frequency_matches]
        findings.append("Message Frequency: " + ", ".join(set(formatted)))


    return findings, has_frequency_estimate
def render_fields_grouped(fields) -> str:
    groups = defaultdict(list)

    for f in fields:
        name = f.get('name', '[no name]')
        ftype = f.get('type', 'text')
        required = "required" if f.get('required', False) else "optional"
        is_sms = f.get('sms_consent', False)
        name_lower = name.lower()

        # Grouping labels - ASCII-friendly
        if ftype == "tel" or "phone" in name_lower or "mobile" in name_lower:
            label = "Phone Fields"
        elif is_sms or "sms" in name_lower or "text" in name_lower:
            label = "SMS Consent Fields"
        elif "email" in name_lower:
            label = "Email Fields"
        elif "consent" in name_lower:
            label = "General Consent Fields"
        else:
            label = "Other Fields"

        groups[label].append(f"- {name} ({ftype}, {required})")

    # Build output text
    output_lines = []
    for group_label, entries in groups.items():
        output_lines.append(f"\n{group_label}:")
        output_lines.extend(entries)

    return "\n".join(output_lines)
# --- GUI App Class ---
class WebScraperApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Privacy/Terms Web Scraper")
        self.theme = tk.StringVar(value='dark')

        # --- Main Controls ---
        self.url_label = tk.Label(root, text="Enter URL:")
        self.url_entry = tk.Entry(root, width=50)
        self.scrape_button = tk.Button(root, text="Scrape", command=self.scrape)
        self.theme_toggle = tk.Checkbutton(root, text="Dark Mode", variable=self.theme, onvalue='dark', offvalue='light', command=self.toggle_theme)
        self.result_box = scrolledtext.ScrolledText(root, width=60, height=15, wrap=tk.WORD)

        # --- Additional Dropdowns ---
        self.depth_label = tk.Label(root, text="Crawl Depth:")
        self.depth_var = tk.StringVar(value="30")
        self.depth_menu = tk.OptionMenu(root, self.depth_var, "30", "50", "100")

        self.kb_label = tk.Label(root, text="Knowledge Base:")
        self.kb_var = tk.StringVar(value="Unite")
        self.kb_menu = tk.OptionMenu(root, self.kb_var, "Unite", "Elevate", "Ascend")

        # --- Layout ---
        self.root.resizable(True, True)
        self.url_label.grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        self.scrape_button.grid(row=0, column=2, padx=5, pady=5)
        self.theme_toggle.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        self.result_box.grid(row=2, column=0, columnspan=3, padx=5, pady=5)

        self.depth_label.grid(row=3, column=0, sticky='w', padx=5)
        self.depth_menu.grid(row=3, column=1, padx=5)
        self.kb_label.grid(row=5, column=0, sticky='w', padx=5)
        self.kb_menu.grid(row=5, column=1, padx=5)
        self.root.rowconfigure(2, weight=1)
        self.root.columnconfigure(1, weight=1)
        self.result_box.grid(sticky="nsew", row=2, column=0, columnspan=3, padx=5, pady=5)


        # ✅ Safe to call after all widgets are defined
        self.theme_toggle.select()
        self.toggle_theme()
    def scrape(self):
        url_input = self.url_entry.get()
        self.result_box.delete(1.0, tk.END)

        is_valid, url = validate_and_normalize_url(url_input)
        if not is_valid:
            messagebox.showerror("Error", "Invalid URL format.")
            return

        crawl_depth = int(self.depth_var.get())
        if not check_robots_txt_allows(url):
            self.result_box.insert(tk.END, f"{ROBOTS_TXT_DISALLOWED_MSG}\n")
            return

        self.root.update_idletasks()

        crawl_results = self.crawl_entire_site(url, max_pages=crawl_depth, delay=CRAWL_DELAY)
        summary = self.summarize_crawl_results(crawl_results)

        self.result_box.delete(1.0, tk.END)
        self.result_box.insert(tk.END, summary)

        # ✅ Make URLs clickable
        self.make_links_clickable()
    def make_links_clickable(self):
        content = self.result_box.get("1.0", tk.END)
        url_pattern = re.compile(r"https?://[^\s)]+")  # Match links and avoid closing parens

        for match in url_pattern.finditer(content):
            url = match.group()
            start = f"1.0 + {match.start()} chars"
            end = f"{start} + {len(url)}c"

            self.result_box.tag_add(url, start, end)
            self.result_box.tag_config(url, foreground="blue", underline=1)
            self.result_box.tag_bind(url, "<Button-1>", lambda e, u=url: webbrowser.open_new_tab(u))
            self.result_box.tag_bind(url, "<Enter>", lambda e: self.result_box.config(cursor="hand2"))
            self.result_box.tag_bind(url, "<Leave>", lambda e: self.result_box.config(cursor=""))
    def toggle_theme(self):
        theme = self.theme.get()
        bg = '#2e2e2e' if theme == 'dark' else 'white'
        fg = 'white' if theme == 'dark' else 'black'

        self.root.configure(bg=bg)
        
        # Labels and Entry
        self.url_label.configure(bg=bg, fg=fg)
        self.depth_label.configure(bg=bg, fg=fg)
        self.kb_label.configure(bg=bg, fg=fg)

        # Entry and Buttons
        self.url_entry.configure(bg=bg, fg=fg, insertbackground=fg)
        self.scrape_button.configure(bg=bg, fg=fg)
        self.theme_toggle.configure(bg=bg, fg=fg)

        # ScrolledText Output Box
        self.result_box.configure(bg=bg, fg=fg, insertbackground=fg)

        # Dropdown menus (Note: platform support may vary)
        self.kb_menu.configure(bg=bg, fg=fg)


    def crawl_entire_site(self, start_url: str, max_pages: int = 30, delay: float = 0.5) -> dict:
        from urllib.parse import urlparse, urljoin
        from bs4 import BeautifulSoup
        import requests
        import time

        visited = set()
        to_visit = [start_url]
        results = {}

        parsed_home = urlparse(start_url)
        base_netloc = parsed_home.netloc

        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop(0)
            if current_url in visited:
                continue
            try:
                response = requests.get(current_url, timeout=10, headers={'User-Agent': 'ComplianceBot/1.5'})
                if response.status_code != 200:
                    continue
                html = response.text
                results[current_url] = html
                visited.add(current_url)
                soup = BeautifulSoup(html, 'html.parser')

                # Extract internal links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(current_url, href)
                    parsed = urlparse(full_url)
                    # Stay on same domain and avoid fragments, mailto, etc.
                    if parsed.netloc == base_netloc and parsed.scheme in ['http', 'https']:
                        clean_url = parsed.scheme + '://' + parsed.netloc + parsed.path
                        if clean_url not in visited and clean_url not in to_visit:
                            to_visit.append(clean_url)
            except Exception:
                continue
            time.sleep(delay)

        return results


    def summarize_crawl_results(self, crawl_results: dict) -> str:
        summary_lines = []
        all_methods_found_urls = []
        all_notices = set()
        all_emails = set()
        all_phones = set()
        all_findings = set()
        policy_links = {}
        detected_fields = []


        for url, html in crawl_results.items():
            soup = BeautifulSoup(html, 'html.parser')
            emails, phones = extract_contact_info(soup)
            all_emails.update(emails)
            all_phones.update(phones)

            # ✅ FIXED: call find_policy_links
            links = find_policy_links(html, url)
            for k, v in links.items():
                if k not in policy_links:
                    policy_links[k] = v

            findings, has_freq = check_compliance_features(html)
            if findings:
                all_findings.update(findings)
            if not has_freq:
                all_findings.add("⚠️ No estimated frequency (e.g., '3 per day') found.")


            lower_text = normalize_text(soup.get_text())
            for method, keywords in FUZZY_METHOD_KEYWORDS.items():
                if any(k in lower_text for k in keywords):
                    all_notices.add(method)
                    all_methods_found_urls.append((url, method))
         # --- Timestamp ---
        summary_lines.append(f"\n🕓 Scan completed on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                 
        # Always include domain
        primary_domain = extract_primary_domain(next(iter(crawl_results.keys()), ""))
        summary_lines.append(f"🔍 Scanned Primary Domain: {primary_domain}")

        # --- TCR Compliance Advisory ---
        kb_choice = self.kb_var.get()
        summary_lines.append("\n📣 SMS Policy Advisory:")
        summary_lines.append("- TCR (The Campaign Registry) requires a valid Privacy Policy on the website for SMS policies")
        summary_lines.append(f"- Click Downloads and load the SMS Privacy Policy and Terms and Conditions Template for {kb_choice}")
        summary_lines.append(f"- {KB_LINKS.get(kb_choice, 'https://support.intermedia.com')}")

        # --- Policy Links ---
        if policy_links:
            summary_lines.append("\n📄 Policy Links Found:")
            for k, v in policy_links.items():
                summary_lines.append(f"- {k}: {v}")

        # --- Contact Info ---
        if all_emails or all_phones:
            summary_lines.append("\n📞 Contact Info Found:")
            if all_emails:
                summary_lines.append(f"- Emails: {', '.join(sorted(all_emails))}")
            if all_phones:
                summary_lines.append(f"- Phones: {', '.join(sorted(all_phones))}")

        # --- Compliance Features ---
        if all_findings:
            summary_lines.append("\n✅ Compliance Features Detected:")
            summary_lines.extend(f"- {finding}" for finding in sorted(all_findings))
        else:
            summary_lines.append("\n⚠️ No compliance keywords or disclosures found.")

        # --- Consent Methods ---
        if all_notices:
            summary_lines.append("\n📝 Consent Methods Detected:")
            summary_lines.extend(f"- {notice}" for notice in sorted(all_notices))

        # --- Form Fields (optional) ---
        if 'detected_fields' in locals() and detected_fields:
            summary_lines.append("\n🧾 Form Field Summary:")
            summary_lines.append(render_fields_grouped(detected_fields))

        # --- Fallback if totally empty ---
        if len(summary_lines) <= 2:  # only domain + TCR info
            summary_lines.append("No compliance features, contact info, or policies found.")


        return "\n".join(summary_lines)

def launch_app():
    root = tk.Tk()
    app = WebScraperApp(root)
    root.mainloop()

if __name__ == '__main__':
    launch_app()
