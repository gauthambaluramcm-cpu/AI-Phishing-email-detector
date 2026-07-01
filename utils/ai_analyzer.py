from openai import OpenAI
import json
import os
import re


def analyze_email(email_text: str) -> dict:
    client = OpenAI(
        api_key=os.getenv("OPENAI_API_KEY", "dummy-key"),
        base_url=os.getenv("OPENAI_BASE_URL")
    )

    prompt = f"""
You are a cybersecurity expert specializing in phishing email detection.
Analyze the following email and return ONLY a valid JSON object — no markdown, no backticks, no explanation.

Email to analyze:
---
{email_text}
---

Return this exact JSON structure:
{{
  "risk_level": "HIGH" | "MEDIUM" | "SAFE",
  "risk_score": <integer 0-100>,
  "summary": "<2-3 sentence plain-English verdict>",
  "red_flags": [
    {{
      "category": "<e.g. Urgency Language / Sender Spoofing / Suspicious Link / Impersonation / Grammar Issues>",
      "detail": "<specific explanation of what was found>",
      "severity": "HIGH" | "MEDIUM" | "LOW"
    }}
  ],
  "urls_found": ["<url1>", "<url2>"],
  "action_guide": {{
    "primary_action": "<Delete Immediately / Report to IT / Verify Before Acting / Safe to Proceed>",
    "steps": [
      "<step 1>",
      "<step 2>",
      "<step 3>"
    ]
  }},
  "legitimate_elements": ["<any element that could fool users>"],
  "education_tip": "<one key cybersecurity lesson from this email>"
}}

Rules:
- risk_score 80-100 = HIGH, 40-79 = MEDIUM, 0-39 = SAFE
- Be specific about red flags, reference actual text from the email
- URLs found should be raw URLs extracted from the email body
- If no red flags found, return empty array and SAFE rating
- Return ONLY the JSON, nothing else
"""

    response = client.chat.completions.create(
        model="gpt-oss-120b",
        messages=[
            {"role": "user", "content": prompt}
        ],
        temperature=0.0
    )
    raw = response.choices[0].message.content.strip()

    # Strip markdown fences if present
    raw = re.sub(r'^```(?:json)?\s*', '', raw)
    raw = re.sub(r'\s*```$', '', raw)

    result = json.loads(raw)
    return result


def extract_eml_content(eml_bytes: bytes) -> str:
    import email
    from email import policy

    msg = email.message_from_bytes(eml_bytes, policy=policy.default)

    parts = []
    parts.append(f"From: {msg.get('From', 'Unknown')}")
    parts.append(f"To: {msg.get('To', 'Unknown')}")
    parts.append(f"Subject: {msg.get('Subject', 'No Subject')}")
    parts.append(f"Date: {msg.get('Date', 'Unknown')}")
    parts.append(f"Reply-To: {msg.get('Reply-To', 'Not set')}")
    parts.append(f"Return-Path: {msg.get('Return-Path', 'Not set')}")
    parts.append("")

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
            elif content_type == 'text/html':
                try:
                    parts.append(f"[HTML BODY]: {part.get_content()}")
                except Exception:
                    pass
    else:
        try:
            parts.append(msg.get_content())
        except Exception:
            parts.append(str(msg.get_payload()))

    return "\n".join(parts)