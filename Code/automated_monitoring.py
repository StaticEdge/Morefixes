import os
import json
import time
import requests
from datetime import datetime, timezone, timedelta

# NVD API endpoints and constants
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
SYNC_META_FILE = "sync_meta.json"
RESULTS_PER_PAGE = 2000

def get_api_key():
    """Retrieve NVD API key from environment variables."""
    return os.environ.get("NVD_API_KEY", "")

def load_checkpoint():
    """Load the last modified start date from the checkpoint file."""
    if os.path.exists(SYNC_META_FILE):
        try:
            with open(SYNC_META_FILE, 'r') as f:
                data = json.load(f)
                checkpoint_date = data.get("lastModStartDate")
                if checkpoint_date:
                    return checkpoint_date
        except json.JSONDecodeError:
            pass
    
    # If no valid checkpoint, return a default date (e.g., 7 days ago)
    default_start = datetime.now(timezone.utc) - timedelta(days=7)
    return default_start.strftime("%Y-%m-%dT%H:%M:%S.000")

def save_checkpoint(last_mod_start_date):
    """Save the last modified start date to the checkpoint file."""
    with open(SYNC_META_FILE, 'w') as f:
        json.dump({"lastModStartDate": last_mod_start_date}, f, indent=4)

def is_fix_link(url):
    """
    Check if the URL is a likely fix link.
    Only include references that contain github.com or gitlab.com
    and keywords like /commit/, /pull/, /merge/, or /patches/.
    """
    if not url:
        return False
        
    url_lower = url.lower()
    if "github.com" in url_lower or "gitlab.com" in url_lower:
        keywords = ["/commit/", "/pull/", "/merge/", "/patches/"]
        return any(keyword in url_lower for keyword in keywords)
    return False

def make_request_with_retry(url, headers, params, max_retries=5):
    """Make requests with robust retry logic for 403/503 errors."""
    for attempt in range(max_retries):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=30)
            if response.status_code == 200:
                return response.json()
            elif response.status_code in [403, 503]:
                # NVD rate limit or service unavailable, exponential backoff
                wait_time = (2 ** attempt) + 0.6
                print(f"Received HTTP {response.status_code}. Retrying in {wait_time}s...")
                time.sleep(wait_time)
            elif response.status_code == 404:
                print("Endpoint not found. Returning empty.")
                return None
            else:
                print(f"Error HTTP {response.status_code}: {response.text}")
                response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Request exception: {e}")
            wait_time = (2 ** attempt) + 0.6
            time.sleep(wait_time)
    
    raise Exception("Max retries exceeded when reaching NVD API.")

def fetch_actionable_cves():
    """
    Fetch CVEs modified since the last checkpoint, filter for actionable targets,
    and return them as a list of dictionaries for MoreFixes.
    
    Returns:
        A list of dictionaries containing cve_id, fix_links, and description.
    """
    last_mod_start = load_checkpoint()
    # End date is now
    last_mod_end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    api_key = get_api_key()
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    actionable_targets = []
    start_index = 0
    total_results = float('inf')

    while start_index < total_results:
        params = {
            "lastModStartDate": last_mod_start,
            "lastModEndDate": last_mod_end,
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index
        }

        print(f"Fetching vulnerabilities from index {start_index}...")
        data = make_request_with_retry(NVD_CVE_API, headers, params)
        
        if not data:
            break
        
        if total_results == float('inf'):
            total_results = data.get("totalResults", 0)
            print(f"Total results to fetch: {total_results}")
            
        if total_results == 0:
            print("No new vulnerabilities found.")
            break
        
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            break
            
        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                continue
                
            # Extract descriptions
            descriptions = cve.get("descriptions", [])
            eng_desc = next((d.get("value") for d in descriptions if d.get("lang") == "en"), "")
            if not eng_desc and descriptions:
                eng_desc = descriptions[0].get("value", "")

            # Filter references
            references = cve.get("references", [])
            fix_links = []
            for ref in references:
                url = ref.get("url", "")
                if is_fix_link(url):
                    fix_links.append(url)
            
            # Add to actionable targets if there are any fix links
            if fix_links:
                actionable_targets.append({
                    "cve_id": cve_id,
                    "fix_links": fix_links,
                    "description": eng_desc
                })
        
        start_index += RESULTS_PER_PAGE
        
        # NVD recommends a sleep of 0.6 seconds with an API key
        # We enforce it regardless to avoid limits
        time.sleep(0.6)

    # After successfully checking all pages, update the checkpoint
    save_checkpoint(last_mod_end)
    print(f"Checkpoint updated. Found {len(actionable_targets)} actionable targets.")
    
    return actionable_targets

if __name__ == "__main__":
    cves = fetch_actionable_cves()
    
    # Optional: Print first few for verification
    if cves:
        print("Sample of actionable CVEs:")
        print(json.dumps(cves[:2], indent=4))
