import logging
import os
import re
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger("LunarGuard.AI")

# Default lightweight model requested
DEFAULT_MODEL_NAME = "google/mobilebert-uncased"

class MobileBertAnalyzer:
    """Lightweight AI Assistant utilizing google/mobilebert-uncased

    for email & log analysis when users are away or offline.
    """

    def __init__(self, model_name: str = DEFAULT_MODEL_NAME):
        self.model_name = model_name
        self.tokenizer = None
        self.model = None
        self.is_loaded = False
        self.loading_error: Optional[str] = None
        self._lock = threading.Lock()

    def load_model_in_background(self):
        """Asynchronously load the MobileBERT model and tokenizer in a background thread."""
        thread = threading.Thread(target=self._load_model, daemon=True)
        thread.start()

    def _load_model(self):
        with self._lock:
            if self.is_loaded:
                return
            try:
                from transformers import AutoModelForSequenceClassification, AutoTokenizer
                import torch

                logger.info(f"Loading MobileBERT model: {self.model_name}")
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
                
                # MobileBERT sequence classification or base model loading
                try:
                    self.model = AutoModelForSequenceClassification.from_pretrained(
                        self.model_name, num_labels=2
                    )
                except Exception:
                    from transformers import AutoModel
                    self.model = AutoModel.from_pretrained(self.model_name)

                self.model.eval()
                self.is_loaded = True
                self.loading_error = None
                logger.info("MobileBERT model loaded successfully.")
            except Exception as exc:
                self.loading_error = str(exc)
                logger.warning(
                    f"MobileBERT model load deferred/failed: {exc}. "
                    "Fallback heuristic mode will be used."
                )

    def _heuristic_email_risk(self, subject: str, body: str) -> Dict[str, Any]:
        """Heuristic risk analysis for emails when model is offline or loading."""
        text = f"{subject} {body}".lower()
        risk_score = 0.0
        flags = []

        phishing_keywords = [
            "urgent action required", "verify your account", "password reset",
            "bank account", "wire transfer", "unusual sign-in", "click here immediately",
            "security alert", "suspicious activity", "invoice attached"
        ]

        for kw in phishing_keywords:
            if kw in text:
                risk_score += 0.25
                flags.append(f"Suspicious phrase: '{kw}'")

        # Check for suspicious external URLs or IP addresses in body
        urls = re.findall(r'https?://[^\s>"]+', body)
        if urls:
            flags.append(f"Contains {len(urls)} external URL(s)")
            risk_score += 0.15

        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', body):
            flags.append("Contains raw IP address URL")
            risk_score += 0.3

        risk_score = min(1.0, risk_score)
        severity = "HIGH" if risk_score >= 0.7 else ("MEDIUM" if risk_score >= 0.4 else "LOW")

        return {
            "risk_score": round(risk_score, 2),
            "severity": severity,
            "flags": flags,
            "ai_engine": "Heuristic Rules (MobileBERT Standby)"
        }

    def analyze_email(self, subject: str, body: str, sender: Optional[str] = None) -> Dict[str, Any]:
        """Analyze email subject and body for security threats, phishing, or anomalies."""
        heuristic_res = self._heuristic_email_risk(subject, body)

        if not self.is_loaded or self.model is None or self.tokenizer is None:
            return {
                "subject": subject,
                "sender": sender or "unknown",
                "summary": subject[:100] if subject else "No Subject",
                **heuristic_res,
                "model_status": "standby" if not self.loading_error else "fallback",
            }

        try:
            import torch

            full_text = f"Subject: {subject}. Body: {body[:512]}"
            inputs = self.tokenizer(
                full_text,
                return_tensors="pt",
                truncation=True,
                max_length=128,
                padding=True,
            )

            with torch.no_grad():
                outputs = self.model(**inputs)
                
            if hasattr(outputs, "logits"):
                probs = torch.softmax(outputs.logits, dim=-1)[0]
                ai_risk = float(probs[1].item()) if probs.shape[0] > 1 else float(probs[0].item())
            else:
                # Feature extraction pooled representation
                last_hidden = outputs.last_hidden_state
                ai_risk = float(torch.sigmoid(last_hidden.mean()).item())

            # Blend AI inference with heuristic risk rules
            combined_risk = round(0.6 * ai_risk + 0.4 * heuristic_res["risk_score"], 2)
            severity = "HIGH" if combined_risk >= 0.7 else ("MEDIUM" if combined_risk >= 0.4 else "LOW")

            return {
                "subject": subject,
                "sender": sender or "unknown",
                "summary": subject[:100] if subject else "No Subject",
                "risk_score": combined_risk,
                "ai_confidence": round(ai_risk, 2),
                "severity": severity,
                "flags": heuristic_res["flags"],
                "ai_engine": f"MobileBERT ({self.model_name})",
                "model_status": "active",
            }
        except Exception as exc:
            logger.error(f"MobileBERT inference error: {exc}")
            return {
                "subject": subject,
                "sender": sender or "unknown",
                "summary": subject[:100] if subject else "No Subject",
                **heuristic_res,
                "model_status": f"error ({exc})",
            }

    def analyze_log(self, log_msg: str, tag: str = "[SYS]") -> Dict[str, Any]:
        """Analyze security or system log entry when user is away."""
        text = f"{tag} {log_msg}"
        
        # Quick keyword heuristic
        lowered = text.lower()
        is_suspicious = any(
            k in lowered
            for k in [
                "failed", "denied", "critical", "unauthorized", "clear",
                "brute", "privilege", "exploit", "attack", "malware", "virus"
            ]
        )

        anomaly_score = 0.8 if is_suspicious else 0.1

        if self.is_loaded and self.model and self.tokenizer:
            try:
                import torch
                inputs = self.tokenizer(
                    text, return_tensors="pt", truncation=True, max_length=128
                )
                with torch.no_grad():
                    outputs = self.model(**inputs)
                
                if hasattr(outputs, "logits"):
                    probs = torch.softmax(outputs.logits, dim=-1)[0]
                    model_score = float(probs[-1].item())
                    anomaly_score = round(0.5 * anomaly_score + 0.5 * model_score, 2)
            except Exception:
                pass

        return {
            "log_message": log_msg,
            "tag": tag,
            "anomaly_score": anomaly_score,
            "is_anomaly": anomaly_score >= 0.5,
            "recommended_action": "Flag for Review" if anomaly_score >= 0.5 else "Ignore",
            "ai_engine": f"MobileBERT ({self.model_name})" if self.is_loaded else "Heuristic Standby"
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "is_loaded": self.is_loaded,
            "loading_error": self.loading_error,
            "description": "Lightweight MobileBERT AI engine for offline/background log and email security analysis.",
            "backend": "transformers + PyTorch" if self.is_loaded else "Heuristic Standby"
        }

# Global singleton instance for LunarGuard AI
AI_ASSISTANT = MobileBertAnalyzer(DEFAULT_MODEL_NAME)
