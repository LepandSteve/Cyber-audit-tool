import re
import requests
from functools import lru_cache
from typing import Optional, List, Tuple


def extract_keywords_from_banner(banner):
    # Extract potential software keywords from banner text
    pattern = re.compile(r"([a-zA-Z0-9\-_.]+(?:\s+[0-9]+\.[0-9]+(?:\.[0-9]+)?)?)")
    matches = pattern.findall(banner)
    keywords = [m.strip() for m in matches if len(m.strip()) > 2]
    return keywords


@lru_cache(maxsize=256)
def query_nvd_api(keyword: str):
    """
    Query NIST NVD API for CVEs matching keyword.
    Returns a list of CVE dicts or raises Exception on failure.
    """
    if not keyword or keyword.strip().lower() in ["no", "none", "n/a", "unknown"] or len(keyword.strip()) < 3:
        return []

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 3,
    }
    headers = {
        "User-Agent": "DGDI CyberAudit Tool"
    }

    resp = requests.get(url, params=params, headers=headers, timeout=6)
    resp.raise_for_status()
    data = resp.json()

    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descriptions = cve.get("descriptions", [])
        summary = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                summary = desc.get("value")
                break
        # CVSS score might be nested under metrics
        cvss_score = 0.0
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
        elif "cvssMetricV30" in metrics:
            cvss_score = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
        elif "cvssMetricV2" in metrics:
            cvss_score = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

        cves.append({
            "id": cve_id,
            "cvss": cvss_score,
            "summary": summary or "No summary available",
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id.startswith("CVE-") else None
        })

    return cves


@lru_cache(maxsize=256)
def query_circl_api(keyword: str):
    """
    Query CIRCL CVE API as a fallback.
    Returns list of CVE dicts or raises Exception on failure.
    """
    if not keyword or keyword.strip().lower() in ["no", "none", "n/a", "unknown"] or len(keyword.strip()) < 3:
        return []

    url = f"https://cve.circl.lu/api/search/{keyword}"
    resp = requests.get(url, timeout=5)
    resp.raise_for_status()
    data = resp.json()

    results = []
    for entry in data.get("data", [])[:3]:
        cve_id = entry.get("id", "N/A")
        results.append({
            "id": cve_id,
            "cvss": entry.get("cvss", 0.0) or 0.0,
            "summary": entry.get("summary", "No summary available"),
            "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}" if cve_id.startswith("CVE-") else None
        })
    return results


def run_audit(
    ip: Optional[str] = None,
    banners: Optional[List[Tuple[int, str]]] = None,
    is_private: Optional[bool] = None,
    open_ports=None,
    shared_data: Optional[dict] = None
) -> dict:
    if is_private:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": "ℹ️ CVE lookup skipped for private/internal IP.",
            "remediation": "✅ No action required for internal-only systems."
        }

    if not banners:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": "❌ Missing input: banners list is required by CVE lookup module.",
            "remediation": "🔧 Ensure banner grabbing runs first and passes data into this module."
        }

    keywords = []
    for _, banner in banners:
        keywords.extend(extract_keywords_from_banner(banner))
    keywords = list(dict.fromkeys(keywords))

    if not keywords:
        return {
            "score": 0.0,
            "status": "Fail",
            "details": "❌ No suitable keywords extracted from banners for CVE lookup.",
            "remediation": "🔧 Improve banner grabbing to capture software names and versions."
        }

    details = "🔍 CVE Lookup Results:\n"
    all_cves = []
    cvss_scores = []

    for keyword in keywords[:3]:
        try:
            results = query_nvd_api(keyword)
        except Exception as e_nvd:
            # Fallback to CIRCL API
            try:
                results = query_circl_api(keyword)
            except Exception as e_circl:
                details += f"\n⚠️ Keyword '{keyword}': CVE lookup failed with errors:\n- NVD API: {e_nvd}\n- CIRCL API: {e_circl}\n"
                continue

        if not results:
            details += f"\n⚠️ Keyword '{keyword}': No CVE data found.\n"
            continue

        details += f"\nKeyword '{keyword}':\n"
        for cve in results:
            try:
                cvss_score = float(cve["cvss"])
            except (ValueError, TypeError):
                cvss_score = 0.0
            cvss_scores.append(cvss_score)
            cve_line = f"• {cve['id']} (CVSS: {cve['cvss']}): {cve['summary']}"
            if cve["url"]:
                cve_line += f" [More Info]({cve['url']})"
            details += cve_line + "\n"
            all_cves.append(cve)

    if not cvss_scores:
        return {
            "score": 10.0,
            "status": "Pass",
            "details": details.strip(),
            "remediation": "✅ No known vulnerabilities found for detected software."
        }

    avg_cvss = sum(cvss_scores) / len(cvss_scores)
    score = max(0.0, 10.0 - avg_cvss)

    if avg_cvss >= 7.0:
        status = "Fail"
    elif avg_cvss >= 4.0:
        status = "Warning"
    else:
        status = "Pass"

    remediation = (
        "🛡️ Remediation Guidance:\n"
        "- Prioritize patching CVEs with CVSS ≥ 7.0.\n"
        "- Follow vendor advisories and mitigation steps.\n"
        "- Regularly update affected software and libraries."
    )

    return {
        "score": round(score, 2),
        "status": status,
        "details": details.strip(),
        "remediation": remediation
    }


if __name__ == "__main__":
    test_banners = [
        (80, "nginx 1.18.0"),
        (443, "OpenSSL 1.1.1"),
        (22, "OpenSSH_7.4p1 Debian-10+deb9u7"),
        (8080, "Apache Tomcat/9.0.37"),
    ]
    result = run_audit(banners=test_banners)
    print(f"Score: {result['score']}\nStatus: {result['status']}\nDetails:\n{result['details']}\nRemediation:\n{result['remediation']}")
