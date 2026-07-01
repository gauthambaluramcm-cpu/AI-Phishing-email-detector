import os
from supabase import create_client, Client
from datetime import datetime


def get_client() -> Client:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    return create_client(url, key)


def save_scan(email_preview: str, risk_level: str, risk_score: int,
              summary: str, red_flags: list, url_results: list,
              action: str) -> dict:
    try:
        client = get_client()
        record = {
            "email_preview": email_preview[:300],
            "risk_level": risk_level,
            "risk_score": risk_score,
            "summary": summary,
            "red_flag_count": len(red_flags),
            "url_count": len(url_results),
            "action": action,
            "scanned_at": datetime.utcnow().isoformat()
        }
        response = client.table("phishing_scans").insert(record).execute()
        return response.data[0] if response.data else {}
    except Exception as e:
        print(f"DB save error: {e}")
        return {}


def get_scan_history(limit: int = 20) -> list:
    try:
        client = get_client()
        response = (
            client.table("phishing_scans")
            .select("*")
            .order("scanned_at", desc=True)
            .limit(limit)
            .execute()
        )
        return response.data or []
    except Exception as e:
        print(f"DB fetch error: {e}")
        return []