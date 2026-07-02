import os
from supabase import create_client, Client
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


def get_client() -> Client:
    url = os.getenv("SUPABASE_URL")
    key = os.getenv("SUPABASE_KEY")
    return create_client(url, key)


def upsert_google_user(google_id: str, email: str, name: str = None):
    """Create or fetch a user authenticated via Google OAuth."""
    try:
        client = get_client()

        # Check if user already exists by google_id
        existing = client.table("app_users").select("*").eq("google_id", google_id).execute()
        if existing.data:
            user_data = existing.data[0]
        else:
            # Check if email already registered (email/password account)
            existing_email = client.table("app_users").select("*").eq("email", email).execute()
            if existing_email.data:
                # Link google_id to existing email account
                user_data = existing_email.data[0]
                client.table("app_users").update({"google_id": google_id}).eq("id", user_data["id"]).execute()
            else:
                # Create new user
                record = {
                    "email": email,
                    "google_id": google_id,
                    "password_hash": None,
                }
                if name:
                    record["name"] = name
                response = client.table("app_users").insert(record).execute()
                if not response.data:
                    return None, "Failed to create user"
                user_data = response.data[0]

        class DummyUser:
            def __init__(self, uid, uemail):
                self.id = uid
                self.email = uemail

        class DummyRes:
            def __init__(self, user):
                self.user = user

        return DummyRes(DummyUser(user_data["id"], user_data["email"])), None

    except Exception as e:
        print(f"Google upsert error: {e}")
        return None, str(e)

def sign_up_user(email: str, password: str):
    try:
        client = get_client()
        
        # Check if user already exists
        existing = client.table("app_users").select("id").eq("email", email).execute()
        if existing.data:
            return None, "User with this email already exists"
            
        hashed_pw = generate_password_hash(password)
        
        record = {
            "email": email,
            "password_hash": hashed_pw
        }
        
        response = client.table("app_users").insert(record).execute()
        if not response.data:
            return None, "Failed to create user"
            
        user_data = response.data[0]
        
        class DummyUser:
            def __init__(self, uid, uemail):
                self.id = uid
                self.email = uemail
        class DummyRes:
            def __init__(self, user):
                self.user = user
                
        return DummyRes(DummyUser(user_data['id'], user_data['email'])), None
        
    except Exception as e:
        print(f"Sign up error: {e}")
        return None, str(e)


def sign_in_user(email: str, password: str):
    try:
        client = get_client()
        
        response = client.table("app_users").select("*").eq("email", email).execute()
        
        if not response.data:
            return None, "Invalid login credentials"
            
        user_data = response.data[0]
        
        if not check_password_hash(user_data['password_hash'], password):
            return None, "Invalid login credentials"
            
        class DummyUser:
            def __init__(self, uid, uemail):
                self.id = uid
                self.email = uemail
        class DummyRes:
            def __init__(self, user):
                self.user = user
                
        return DummyRes(DummyUser(user_data['id'], user_data['email'])), None
        
    except Exception as e:
        print(f"Sign in error: {e}")
        return None, str(e)


def save_scan(email_preview: str, risk_level: str, risk_score: int,
              summary: str, red_flags: list, url_results: list,
              action: str, user_id: str = None) -> dict:
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
        if user_id:
            record["user_id"] = user_id

        response = client.table("phishing_scans").insert(record).execute()
        return response.data[0] if response.data else {}
    except Exception as e:
        print(f"DB save error: {e}")
        return {}


def get_scan_history(user_id: str = None, limit: int = 20) -> list:
    try:
        client = get_client()
        query = client.table("phishing_scans").select("*")
        if user_id:
            query = query.eq("user_id", user_id)

        response = query.order("scanned_at", desc=True).limit(limit).execute()
        return response.data or []
    except Exception as e:
        print(f"DB fetch error: {e}")
        return []