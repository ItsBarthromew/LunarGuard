import logging
import os
import re
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger("LunarGuard.AI")

DEFAULT_MODEL_NAME = "google/mobilebert-uncased"

# 1 = Bad (Malicious / Phishing Threat)
# 2 = Good (Safe / Clean)
# 3 = Potential Bad (Suspicious / High Urgency - Needs Review)
STATUS_BAD = 1
STATUS_GOOD = 2
STATUS_POTENTIAL_BAD = 3

VERDICT_MAP = {
    STATUS_BAD: "Bad",
    STATUS_GOOD: "Good",
    STATUS_POTENTIAL_BAD: "Potential Bad",
}

class MobileBertAnalyzer:
    """Lightweight AI Assistant utilizing google/mobilebert-uncased

    for email & log analysis, classifying items into:
      1 - Bad (Malicious / Phishing)
      2 - Good (Clean / Safe)
      3 - Potential Bad (Suspicious / High Urgency - Review Required)
    """

    def __init__(self, model_name: str = DEFAULT_MODEL_NAME):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.is_loaded = False
        self.loading_error: Optional[str] = None
        self._lock = threading.Lock()

    def load_model_in_background(self):
        """Asynchronously load MobileBERT model in background."""
        thread = threading.Thread(target=self._load_model, daemon=True)
        thread.start()

    def _load_model(self):
        if self.is_loaded:
            return
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            import torch

            logger.info(f"Loading MobileBERT model: {self.model_name}")
            tokenizer = AutoTokenizer.from_pretrained(self.model_name, local_files_only=False)
            
            try:
                model = AutoModelForSequenceClassification.from_pretrained(
                    self.model_name, num_labels=3, local_files_only=False
                )
            except Exception:
                from transformers import AutoModel
                model = AutoModel.from_pretrained(self.model_name, local_files_only=False)

            model.eval()
            with self._lock:
                self.tokenizer = tokenizer
                self.model = model
                self.is_loaded = True
                self.loading_error = None
            logger.info("MobileBERT model loaded successfully.")
        except Exception as exc:
            with self._lock:
                self.loading_error = str(exc)
            logger.warning(
                f"MobileBERT load deferred/fallback mode enabled: {exc}."
            )

    def _load_whitelist(self) -> set:
        whitelist_path = os.path.join(os.path.dirname(__file__), "data", "whitelisted_domains.txt")
        domains = set()
        if os.path.exists(whitelist_path):
            try:
                with open(whitelist_path, "r") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith("#"):
                            domains.add(line)
            except Exception:
                pass
        return domains

    def _inspect_urls(self, body: str, flags: list) -> float:
        whitelist = self._load_whitelist()
        url_risk = 0.0
        urls = re.findall(r'https?://[^\s>"]+', body)

        for url in urls:
            url_lower = url.lower()
            
            # 1. Flag HTTP vs HTTPS (Insecure protocol)
            if url_lower.startswith("http://"):
                url_risk += 0.25
                flags.append(f"Insecure HTTP protocol used (missing HTTPS): {url[:55]}")

            # 2. Flag file extensions in URL path (.pdf, .exe, .zip, etc.)
            dangerous_extensions = [".pdf", ".exe", ".zip", ".scr", ".bat", ".cmd", ".doc", ".docx", ".xls", ".xlsx", ".iso", ".js", ".vbs"]
            if any(ext in url_lower for ext in dangerous_extensions):
                url_risk += 0.35
                flags.append(f"Suspicious file extension in URL path: {url[:55]}")

            # 3. Whitelist Domain Check
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                hostname = parsed.hostname
                if hostname:
                    hostname = hostname.lower()
                    matched = False
                    for d in whitelist:
                        if hostname == d or hostname.endswith("." + d):
                            matched = True
                            break
                    
                    if not matched:
                        url_risk += 0.30
                        flags.append(f"External domain not on corporate whitelist: '{hostname}'")
            except Exception:
                pass

            # 4. Sensitive keywords in URL
            if any(k in url_lower for k in ["auth", "portal", "reset", "login", "verify", "sso", "company-", "secure", "corp-fileshare", "drive.", "sharepoint", "dropbox"]):
                url_risk += 0.30
                flags.append(f"Sensitive login / file-share link found: {url[:55]}")

        return min(0.9, url_risk)

    def _determine_status(self, score: float):
        """Map 0.0 - 1.0 risk score to 1-Bad, 2-Good, 3-Potential Bad status."""
        if score >= 0.60:
            return STATUS_BAD, VERDICT_MAP[STATUS_BAD]
        elif score >= 0.25:
            return STATUS_POTENTIAL_BAD, VERDICT_MAP[STATUS_POTENTIAL_BAD]
        else:
            return STATUS_GOOD, VERDICT_MAP[STATUS_GOOD]

    def _heuristic_email_risk(self, subject: str, body: str, sender: Optional[str] = None, recipient: Optional[str] = None) -> Dict[str, Any]:
        """Deep pattern matching trained on phishing, credential harvesting, urgency scams, and spam."""
        text = f"{subject} {body}".lower()
        sender_str = str(sender or "").lower()
        recipient_str = str(recipient or "").lower()
        risk_score = 0.0
        flags = []

        # 1. High Urgency & Time Pressure / Rush Tactics
        urgency_patterns = [
            "expire in", "expires in", "24 hours", "48 hours", "12 hours", "expire",
            "immediately", "asap", "deadline", "urgently", "avoid losing access",
            "account will be locked", "account locked", "suspended", "within 24",
            "urgent action", "rush"
        ]
        matched_urgency = [p for p in urgency_patterns if p in text]
        if matched_urgency:
            risk_score += 0.35
            flags.append(f"High urgency / pressure tactic detected: '{matched_urgency[0]}'")

        # 2. Credential Harvesting & Password Phishing Triggers
        credential_patterns = [
            "password is set to expire", "update your credentials", "update credentials",
            "set your new password", "reset your password", "change your password",
            "verify your credentials", "single sign-on portal", "authportal", "login portal",
            "sso portal", "auth portal", "confirm password", "verify your account"
        ]
        matched_cred = [p for p in credential_patterns if p in text]
        if matched_cred:
            risk_score += 0.40
            flags.append(f"Credential harvesting indicator: '{matched_cred[0]}'")

        # 3. IT / Authority Impersonation
        impersonation_patterns = [
            "it infrastructure", "it helpdesk", "system administrator", "security team",
            "corporate password", "it team", "admin team", "helpdesk", "support team"
        ]
        matched_imp = [p for p in impersonation_patterns if p in text]
        if matched_imp:
            risk_score += 0.20
            flags.append(f"Corporate / IT team impersonation language: '{matched_imp[0]}'")

        # 4. Moderate Urgency & General Suspicious Triggers
        moderate_patterns = [
            "action needed", "important notification", "account review", "account notifications",
            "limited time", "please review", "unusual activity", "update required"
        ]
        matched_mod = [p for p in moderate_patterns if p in text]
        if matched_mod:
            risk_score += 0.25
            flags.append(f"Moderate urgency / notification indicator: '{matched_mod[0]}'")

        # 5. Business Email Compromise (BEC) & Invoice Wire Fraud
        bec_patterns = [
            "updated bank details", "new bank details", "change of banking", "wire transfer",
            "outstanding vendor payment", "revised invoice", "payment instructions", "banking information"
        ]
        matched_bec = [p for p in bec_patterns if p in text]
        if matched_bec:
            risk_score += 0.45
            flags.append(f"Business Email Compromise (BEC) / Invoice wire fraud indicator: '{matched_bec[0]}'")

        # 6. Malicious Macro / Document Execution Lures
        macro_patterns = [
            "enable macros", "enable content", "enable editing", "digital signature embedded",
            "protected view", "macro-enabled"
        ]
        matched_macro = [p for p in macro_patterns if p in text]
        if matched_macro:
            risk_score += 0.50
            flags.append(f"Dangerous file execution / macro enablement lure: '{matched_macro[0]}'")

        # 7. Comprehensive URL & Whitelist Inspection
        url_risk_add = self._inspect_urls(body, flags)
        risk_score += url_risk_add

        # 7. Unverified sender domain check
        if sender_str and ("@free-mail" in sender_str or "@temp-mail" in sender_str or "admin@" in sender_str or "it@" in sender_str):
            risk_score += 0.25
            flags.append(f"Untrusted sender domain: {sender_str}")

        # 8. Domain Mismatch / Spoofing Analysis between Sender & Recipient
        if sender_str and recipient_str and "@" in sender_str and "@" in recipient_str:
            sender_domain = sender_str.split("@")[-1].strip()
            recipient_domain = recipient_str.split("@")[-1].strip()

            if sender_domain != recipient_domain:
                if matched_imp or matched_cred:
                    risk_score += 0.40
                    flags.append(f"Domain Mismatch: Sender domain '@{sender_domain}' differs from recipient domain '@{recipient_domain}' while claiming internal/IT authority.")
                elif any(w in sender_domain for w in ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]):
                    risk_score += 0.30
                    flags.append(f"Public webmail sender '@{sender_domain}' sending to organization domain '@{recipient_domain}'.")

        risk_score = min(1.0, risk_score)
        rating, verdict = self._determine_status(risk_score)

        return {
            "risk_score": round(risk_score, 2),
            "rating": rating,
            "verdict": verdict,
            "flags": flags,
        }

    def analyze_email(self, subject: str, body: str, sender: Optional[str] = None, recipient: Optional[str] = None) -> Dict[str, Any]:
        """Analyze email for spam/phishing and return 1-Bad, 2-Good, 3-Potential Bad rating."""
        heuristic = self._heuristic_email_risk(subject, body, sender, recipient)
        
        ai_risk = heuristic["risk_score"]
        engine = "Rule Engine (MobileBERT Standby)"

        if self.is_loaded and self.model and self.tokenizer:
            try:
                import torch
                full_text = f"Email Subject: {subject}. Body: {body[:256]}"
                inputs = self.tokenizer(
                    full_text, return_tensors="pt", truncation=True, max_length=128, padding=True
                )
                with torch.no_grad():
                    outputs = self.model(**inputs)

                if hasattr(outputs, "logits"):
                    probs = torch.softmax(outputs.logits, dim=-1)[0]
                    ai_risk = float(probs[-1].item())
                else:
                    last_hidden = outputs.last_hidden_state
                    ai_risk = float(torch.sigmoid(last_hidden.mean()).item())

                engine = f"MobileBERT ({self.model_name})"
            except Exception as exc:
                logger.error(f"MobileBERT evaluation error: {exc}")

        combined_risk = round(0.5 * ai_risk + 0.5 * heuristic["risk_score"], 2)
        rating, verdict = self._determine_status(combined_risk)

        return {
            "rating": rating,
            "verdict": verdict,
            "status_code": f"{rating} - {verdict}",
            "risk_score": combined_risk,
            "subject": subject,
            "sender": sender or "unknown",
            "recipient": recipient or "unknown",
            "flags": heuristic["flags"],
            "ai_engine": engine,
            "explanation": (
                "Phishing / Credential harvesting threat detected (Bad)" if rating == STATUS_BAD else (
                    "High urgency / suspicious indicators found; review recommended (Potential Bad)" if rating == STATUS_POTENTIAL_BAD else
                    "Clean and safe email (Good)"
                )
            )
        }

    def analyze_log(self, log_msg: str, tag: str = "[SYS]") -> Dict[str, Any]:
        """Analyze security log entry and return 1-Bad, 2-Good, 3-Potential Bad rating."""
        text = f"{tag} {log_msg}".lower()
        risk_score = 0.0
        flags = []

        # Bad / Critical indicators
        if any(w in text for w in ["failed logon", "audit log cleared", "brute force", "malware", "encodedcommand", "exfiltration"]):
            risk_score += 0.7
            flags.append("Critical security violation / anomaly pattern detected")

        # Potential Bad / Warning indicators
        elif any(w in text for w in ["unusual hours", "sensitive file", "admin account", "new service", "modified"]):
            risk_score += 0.4
            flags.append("Suspicious activity requiring review")

        rating, verdict = self._determine_status(risk_score)

        return {
            "rating": rating,
            "verdict": verdict,
            "status_code": f"{rating} - {verdict}",
            "risk_score": round(risk_score, 2),
            "log_message": log_msg,
            "tag": tag,
            "flags": flags,
            "ai_engine": f"MobileBERT ({self.model_name})" if self.is_loaded else "Log Pattern Analyzer",
            "explanation": (
                "Threat / Malicious activity in log (Bad)" if rating == STATUS_BAD else (
                    "Suspicious activity detected; review recommended (Potential Bad)" if rating == STATUS_POTENTIAL_BAD else
                    "Routine benign log event (Good)"
                )
            )
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "is_loaded": self.is_loaded,
            "ratings_supported": ["1 - Bad", "2 - Good", "3 - Potential Bad"],
            "description": "MobileBERT assistant classifying email/logs into 1-Bad, 2-Good, 3-Potential Bad.",
            "backend": "transformers + PyTorch" if self.is_loaded else "Pattern Engine Standby"
        }

AI_ASSISTANT = MobileBertAnalyzer(DEFAULT_MODEL_NAME)
