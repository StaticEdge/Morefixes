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

MODEL_NAME = "gemini-2.0-flash"
SLEEP_SECONDS = 1
DELAY_BETWEEN_UPLOADS = 0.5
MAX_RETRIES = 5
# ---------------------------------------

# Configure Gemini
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
model = genai.GenerativeModel(MODEL_NAME)


def analyze_diff_gemini(file_path: str, diff_content: str):
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

        return json.loads(response.text)

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
    print("Scanning for patch files...")
    patch_files = get_patch_files_list(PATCH_DIR)
    print(f"Found {len(patch_files)} patch files.\n")

    results = []

    for i, filename in enumerate(patch_files):
        print(f"[{i+1}/{len(patch_files)}] Processing {filename}")

        diff_content = load_single_patch(PATCH_DIR, filename)
        if not diff_content:
            continue

        analysis = analyze_diff_gemini(filename, diff_content)

        if analysis:
            results.append(analysis)

        time.sleep(SLEEP_SECONDS)

    print(f"\n✅ Done! Processed {len(results)} records.")

    # Upload all results to Supabase as a single JSON file
    if results:
        upload_json_to_supabase(results)
    else:
        print("No results to upload.")
