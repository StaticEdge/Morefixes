import os
import google.generativeai as genai
import json
import time
import boto3
from botocore.exceptions import ClientError
from datetime import datetime
from http.client import RemoteDisconnected

from dotenv import load_dotenv
load_dotenv()

# ---------------- CONFIG ----------------
PATCH_DIR = os.getenv("OUTPUT_FOLDER")
PATCH_FILE_METADATA_PATH = os.getenv("PATCH_FILE_METADATA_PATH", "/pool0/data/user/metadata")

MODEL_NAME = "gemini-2.0-flash"
SLEEP_SECONDS = 1
DELAY_BETWEEN_UPLOADS = 0.5
MAX_RETRIES = 5
# ---------------------------------------

# Configure Gemini
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel(MODEL_NAME)


def analyze_diff_gemini(file_path: str, diff_content: str, cve_id: str | None = None, cwe_ids: list | None = None):
    cve_id_hint = cve_id if cve_id else "unknown — infer from context if possible"
    cwe_ids_hint = json.dumps(cwe_ids) if cwe_ids else "not provided — infer from vulnerability_type and diff"
    prompt = f"""
You are a security researcher analyzing vulnerable code changes for dataset construction.

Your task is to extract an ABSTRACT description of the vulnerability based ONLY on the vulnerable logic.

STRICT RULES FOR DESCRIPTION:
- DO NOT mention variable names, function names, file paths, libraries, or identifiers.
- DO NOT mention line numbers, commits, or patches.
- DO NOT describe the fix itself.
- DO NOT include safe or correct behavior.
- DO NOT include framework-specific APIs unless unavoidable.
Before selecting the vulnerability_type, internally classify the issue.
Then map it to the closest allowed category.
Only output the final mapped value.


FOCUS ON (DESCRIPTION ONLY):
- Code patterns and control/data flow
- How untrusted input, state, or events lead to insecure behavior
- The logical mistake that enabled exploitation

--------------------------------------------------
ADDITIONAL METADATA INSTRUCTIONS:

Using the diff and file context, infer the following fields:
- commitdate: Use ISO format (YYYY-MM-DD) if present in the patch metadata, otherwise use "Unknown".
- vulnerability_type: MUST be selected from the following list (ALLOWED VULNERABILITY TYPES) ONLY.
  You MUST output EXACTLY one value from this list.
  DO NOT invent new labels.
  DO NOT rephrase labels.
  DO NOT change casing or punctuation.
  If none apply with reasonable confidence, output "other".

ALLOWED VULNERABILITY TYPES:
- improper-validation
- mishandled-sensitive-information
- code-injection
- command-injection
- cookie-security
- cross-site-request-forgery-csrf
- cross-site-request-forgery-xss
- cross-site-scripting-xss
- cryptographic-issues
- denial-of-service-dos
- hard-coded-secrets
- improper-authentication
- improper-authorization
- improper-validation
- insecure-hashing-algorithm
- mishandled-sensitive-information
- open-redirect
- path-traversal
- prototype-pollution
- server-side-request-forgery-ssrf
- sql-injection
- xml-injection
- other

SELECTION GUIDELINES:
- Choose the MOST SPECIFIC applicable category.
- Prefer injection-specific labels over generic validation issues.
- Prefer authorization/authentication issues only if access control is bypassed.
- Use denial-of-service-dos ONLY if the primary impact is resource exhaustion or crash.
- Use cryptographic categories ONLY if cryptography is directly misused.
- Do NOT choose multiple labels.
- If the vulnerability spans multiple categories, choose the dominant root cause.


- framework: Programming language or ecosystem (e.g., Go, Java, Python) or "Unknown".
- is_vulnerability_fix: true if the patch mitigates or fixes a vulnerability.
- can_semgrep_catch_by_custom_rule: true if a static pattern-based Semgrep rule could reasonably detect this issue.
- runtime_or_compiletime: Use "runtime" or "compiletime".
- cve_id: The CVE identifier for this vulnerability (e.g. "CVE-2024-1234").
  Use the value provided below if available, otherwise output null.
- cwe_ids: A JSON array of CWE identifiers (e.g. ["CWE-79", "CWE-116"]).
  Use the values provided below if available.
  If NOT provided or empty, INFER the most applicable CWE ID(s) from the
  vulnerability_type and the diff (1–3 CWEs maximum, most specific first).
  Output an empty array [] ONLY if you truly cannot determine any CWE.

--------------------------------------------------
KNOWN IDENTIFIERS (from patch metadata — use as-is if present):
  cve_id  : {cve_id_hint}
  cwe_ids : {cwe_ids_hint}
--------------------------------------------------
--------------------------------------------------
OUTPUT REQUIREMENTS:

Output MUST be valid JSON.
Output MUST contain ONLY the following keys.
Do NOT include any additional keys.
Do NOT nest fields.
Do NOT include analysis, reasoning, or intermediate classifications.

{{
  "commitdate": "<YYYY-MM-DD or 'Unknown'>",
  "vulnerability_type": "<standardized vulnerability category>",
  "framework": "<language or framework or 'Unknown'>",
  "is_vulnerability_fix": <true|false>,
  "can_semgrep_catch_by_custom_rule": <true|false>,
  "runtime_or_compiletime": "<runtime|compiletime>",
  "description": "<5–6 sentence abstract describing the vulnerable logic pattern>",
  "cve_id": "<CVE-YYYY-NNNNN or null>",
  "cwe_ids": ["<CWE-NNN>", "..."],
  "name": "{file_path}"
}}
--------------------------------------------------


Analyze the following code diff and extract the vulnerability abstraction.

Diff:
{diff_content[:25000]}
"""
    try:
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.0,
                "response_mime_type": "application/json"
            }
        )

        result = json.loads(response.text)
        # If Gemini left cve_id/cwe_ids blank but we have them from metadata, override
        if cve_id and not result.get("cve_id"):
            result["cve_id"] = cve_id
        if cwe_ids and not result.get("cwe_ids"):
            result["cwe_ids"] = cwe_ids
        return result

    except Exception as e:
        # # 🔴 Break condition
        # if isinstance(e, RemoteDisconnected) or "Remote end closed connection" in str(e):
        #     raise RuntimeError("FATAL_CONNECTION_ABORT")
        print(f"Error analyzing {file_path}: {e}")
        return None


# ---------- File Utilities ----------
def get_patch_files_list(patch_dir):
    if not os.path.exists(patch_dir):
        print(f"Error: Directory {patch_dir} not found!")
        return []
    return [f for f in os.listdir(patch_dir) if f.endswith(".patch")]


def load_single_patch(patch_dir, filename):
    try:
        with open(os.path.join(patch_dir, filename), "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        print(f"Error reading {filename}: {e}")
        return None


def load_patch_metadata(metadata_dir: str) -> dict:
    """
    Loads patch_metadata.json from the given directory and returns a dict
    keyed by patchfile_name for O(1) lookups.

    Handles cases where 'cwe' may be null or an empty list (known generation bug).
    Returns an empty dict if the file is missing or malformed.
    """
    metadata_path = os.path.join(metadata_dir, "patch_metadata.json")
    if not os.path.exists(metadata_path):
        print(f"⚠️  patch_metadata.json not found at {metadata_path}. CWE/CVE fields will be empty.")
        return {}
    try:
        with open(metadata_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        # Build lookup dict; guard against null/missing cwe (known generation bug)
        lookup = {}
        for entry in raw:
            name = entry.get("patchfile_name", "")
            if name:
                lookup[name] = {
                    "cve_id": entry.get("cve_id") or None,
                    # cwe may be null or [] due to a bug in the metadata generation script
                    "cwe_ids": entry.get("cwe") or [],
                }
        print(f"✅ Loaded patch_metadata.json: {len(lookup)} entries.")
        return lookup
    except Exception as e:
        print(f"⚠️  Failed to load patch_metadata.json: {e}. CWE/CVE fields will be empty.")
        return {}


# ---------- Supabase Upload ----------
def upload_json_to_supabase(data: list):
    """
    Uploads the results list as a uniquely named JSON file to Supabase storage
    using the same boto3/S3-compatible approach as process_and_upload.py.
    """
    s3_endpoint = os.getenv("SUPABASE_URL")
    aws_access_key_id = os.getenv("SUPABASE_KEY_ID")
    aws_secret_access_key = os.getenv("SUPABASE_KEY")
    bucket_name = "description"

    if not all([s3_endpoint, aws_access_key_id, aws_secret_access_key]):
        print("⚠️  Missing Supabase env vars (SUPABASE_URL / SUPABASE_KEY_ID / SUPABASE_KEY). Skipping upload.")
        return

    # Unique filename based on timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    remote_filename = f"vuln_descriptions_{timestamp}.json"

    # Write to a temp local file first
    local_tmp = f"/tmp/{remote_filename}"
    with open(local_tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    s3 = boto3.client(
        "s3",
        endpoint_url=s3_endpoint,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )

    retries = 0
    while retries < MAX_RETRIES:
        try:
            print(f"Uploading {remote_filename} to Supabase bucket '{bucket_name}'...")
            s3.upload_file(
                Filename=local_tmp,
                Bucket=bucket_name,
                Key=remote_filename,
                ExtraArgs={"CacheControl": "3600"},
            )
            print(f"✅ Successfully uploaded {remote_filename} to Supabase.")
            time.sleep(DELAY_BETWEEN_UPLOADS)
            break

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            wait_time = (2 ** retries) + 1
            print(f"Upload error ({error_code}). Retrying in {wait_time}s... ({retries + 1}/{MAX_RETRIES})")
            time.sleep(wait_time)
            retries += 1

    if retries == MAX_RETRIES:
        print(f"❌ Max retries reached. Could not upload {remote_filename}.")

    # Clean up temp file
    try:
        os.remove(local_tmp)
    except OSError:
        pass


# ---------- Main Pipeline ----------
def generate_descriptions():
    print(f"Using patch directory: {PATCH_DIR}")
    print(f"Using metadata directory: {PATCH_FILE_METADATA_PATH}")
    print("Scanning for patch files...")
    patch_files = get_patch_files_list(PATCH_DIR)
    print(f"Found {len(patch_files)} patch files.\n")

    # Load patch metadata once (cve_id + cwe_ids per patch filename)
    patch_metadata = load_patch_metadata(PATCH_FILE_METADATA_PATH)

    results = []

    for i, filename in enumerate(patch_files):
        print(f"[{i+1}/{len(patch_files)}] Processing {filename}")

        diff_content = load_single_patch(PATCH_DIR, filename)
        if not diff_content:
            continue

        # Pass known CVE/CWE hints into Gemini so it can use or infer them
        meta = patch_metadata.get(filename, {})
        known_cve = meta.get("cve_id") or None
        known_cwes = meta.get("cwe_ids") or []

        analysis = analyze_diff_gemini(filename, diff_content, cve_id=known_cve, cwe_ids=known_cwes)

        if analysis:
            if not analysis.get("cve_id"):
                print(f"  ⚠️  No CVE ID found or inferred for {filename}")
            if not analysis.get("cwe_ids"):
                print(f"  ⚠️  CWE IDs missing or could not be inferred for {filename}")
            else:
                src = "metadata" if known_cwes else "inferred by Gemini"
                print(f"  ✅  CWE IDs ({src}): {analysis['cwe_ids']}")

            results.append(analysis)

        time.sleep(SLEEP_SECONDS)

    print(f"\n✅ Done! Processed {len(results)} records.")

    # Upload all results to Supabase as a single JSON file
    if results:
        upload_json_to_supabase(results)
    else:
        print("No results to upload.")
