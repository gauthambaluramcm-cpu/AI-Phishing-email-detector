import requests
import os
import base64
import time


def scan_urls(urls: list) -> list:
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key or not urls:
        return []

    results = []

    for url in urls[:5]:  # Limit to 5 URLs (free tier)
        try:
            result = _scan_single_url(url, api_key)
            results.append(result)
            time.sleep(0.5)
        except Exception as e:
            results.append({
                "url": url,
                "status": "error",
                "error": str(e),
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "verdict": "UNKNOWN"
            })

    return results


def _scan_single_url(url: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}

    # Submit URL for scanning
    submit_resp = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url},
        timeout=10
    )

    if submit_resp.status_code != 200:
        raise Exception(f"Submission failed: {submit_resp.status_code}")

    # Wait then fetch results
    time.sleep(2)

    # URL ID = base64 of the url
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    report_resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers,
        timeout=10
    )

    if report_resp.status_code != 200:
        raise Exception(f"Report fetch failed: {report_resp.status_code}")

    data = report_resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless   = stats.get("harmless", 0)

    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "url": url,
        "status": "scanned",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "verdict": verdict
    }