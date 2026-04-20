import os
import time
import glob
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import requests
from datetime import datetime, timedelta
import json
import subprocess

load_dotenv('.env')

def save_vulnerabilities_to_file(data, folder="Data/json"):
    # Ensure the directory exists
    if not os.path.exists(folder):
        os.makedirs(folder)
    
    # Create a unique filename based on current time
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"nvd_feed_{timestamp}.json"
    filepath = os.path.join(folder, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
    
    print(f"Saved {len(data)} vulnerabilities to {filepath}")
    return filepath

def fetch_latest_cves():
    # Calculate time range (last 12 hours)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(hours=2)
    
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
    params = {
        "lastModStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    }
    headers = {"apiKey": os.getenv("NVD_API_KEY")}
    
    try:
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status() # Check for HTTP errors
        
        full_response = response.json()
        
        # Save the raw data before returning
        # if full_response:
        #     save_vulnerabilities_to_file(full_response)
            
        return full_response
    except Exception as e:
        print(f"Error fetching data: {e}")
        return []

def upload_patches_to_s3():
    """
    Finds .patch files in OUTPUT_FOLDER and uploads them 
    to an S3 bucket (Supabase storage bucket or AWS S3).
    Implements rate-limiting and exponential backoff for retries.
    """
    
    patch_dir = os.getenv("OUTPUT_FOLDER")
    s3_endpoint = os.getenv("SUPABASE_URL")  # e.g., https://xyz.supabase.co/storage/v1
    aws_access_key_id = os.getenv("SUPABASE_KEY_ID")
    aws_secret_access_key = os.getenv("SUPABASE_KEY")
    bucket_name = "morefix"
    
    if not all([patch_dir, s3_endpoint, aws_access_key_id, aws_secret_access_key]):
        print("Missing required environment variables.")
        print("Please ensure OUTPUT_FOLDER, SUPABASE_URL, SUPABASE_KEY_ID, and SUPABASE_KEY are set.")
        return

    if not os.path.exists(patch_dir):
        print(f"Directory {patch_dir} does not exist.")
        return

    # Initialize boto3 S3 client
    s3 = boto3.client(
        "s3",
        endpoint_url=s3_endpoint,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
    )

    # Find all .patch files recursively
    search_pattern = os.path.join(patch_dir, "**", "*.patch")
    patch_files = glob.glob(search_pattern, recursive=True)

    if not patch_files:
        print(f"No .patch files found in {patch_dir}")
        return

    print(f"Found {len(patch_files)} patch files to upload.")

    # Rate limiting configuration
    DELAY_BETWEEN_UPLOADS = 0.5  # Seconds
    MAX_RETRIES = 5

    for file_path in patch_files:
        file_name = os.path.basename(file_path)
        retries = 0

        while retries < MAX_RETRIES:
            try:
                print(f"Uploading {file_name}...")
                s3.upload_file(
                    Filename=file_path,
                    Bucket=bucket_name,
                    Key=file_name,
                    ExtraArgs={
                        "CacheControl": "3600",
                    }
                )
                print(f"Successfully uploaded {file_name}")
                time.sleep(DELAY_BETWEEN_UPLOADS)
                break  # Exit retry loop on success

            except ClientError as e:
                error_code = e.response['Error']['Code']
                print(f"Error uploading {file_name}: {error_code}")
                if error_code in ["Throttling", "SlowDown", "TooManyRequests"]:
                    wait_time = (2 ** retries) + 1
                    print(f"Rate limited. Waiting {wait_time} seconds before retrying...")
                else:
                    wait_time = (2 ** retries) + 1
                    print(f"Temporary error. Retrying in {wait_time} seconds... ({retries+1}/{MAX_RETRIES})")
                time.sleep(wait_time)
                retries += 1

        if retries == MAX_RETRIES:
            print(f"Max retries reached for {file_name}. Skipping.")

def _get_weekly_folder():
    """Get the weekly folder name based on current ISO week, e.g., '2026-W15'."""
    now = datetime.now()
    year, week, _ = now.isocalendar()
    return f"{year}-W{week:02d}"


def _find_cached_repo_path(patch_filename, git_cache_dir="/tmp/proscache"):
    """
    Try to find the cached cloned repo for a patch file.
    
    Patch filenames look like: github.com_openclaw_openclaw_06de515b6c42816b62ec752e1c221cab67b38501.patch
    The repo part is: github.com_openclaw_openclaw
    The cached repo path would be: /tmp/proscache/github.com_openclaw_openclaw
    """
    if not os.path.exists(git_cache_dir):
        return None
    
    # Remove .patch extension and the commit hash (last _ segment)
    base = patch_filename.replace(".patch", "")
    parts = base.rsplit("_", 1)  # Split off the commit hash
    if len(parts) >= 2:
        repo_name = parts[0]  # e.g., github.com_openclaw_openclaw
        repo_path = os.path.join(git_cache_dir, repo_name)
        if os.path.exists(repo_path):
            return repo_path
    
    # Fallback: try to find a matching directory
    for entry in os.listdir(git_cache_dir):
        entry_path = os.path.join(git_cache_dir, entry)
        if os.path.isdir(entry_path) and patch_filename.startswith(entry):
            return entry_path
    
    return None


def run_semgrep_rule_generation():
    """
    Sequential batch runner for semgrep rule generation.
    
    For each patch file in patchesdir/js-ts-patches/:
    1. Find cached repo (if available) for semgrep scanning
    2. Call the sast_rule_agent_temp agent via subprocess
    3. Collect generated rules into a weekly folder
    4. Push rules to git@github.com:StaticEdge/ts-rules.git
    5. Clean up generated rules and cloned repos after successful push
    """
    print("=" * 70)
    print("Starting Semgrep Rule Generation Pipeline")
    print("=" * 70)
    
    # Paths
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    patch_dir = os.path.join(project_root, "patchesdir", "js-ts-patches")
    agent_dir = os.path.join(project_root, "sast_rule_agent_temp")
    git_cache_dir = os.getenv("PROSPECTOR_GIT_CACHE", "/tmp/proscache")
    
    # Weekly output folder
    weekly_folder_name = _get_weekly_folder()
    rules_output_dir = os.path.join(project_root, "tmp", "rules", weekly_folder_name)
    os.makedirs(rules_output_dir, exist_ok=True)
    
    print(f"  Patch directory: {patch_dir}")
    print(f"  Agent directory: {agent_dir}")
    print(f"  Rules output: {rules_output_dir}")
    print(f"  Weekly folder: {weekly_folder_name}")
    print(f"  Git cache: {git_cache_dir}")
    
    # Validate
    if not os.path.exists(patch_dir):
        print(f"No patch directory found: {patch_dir}")
        return
    
    # Discover patches
    patch_files = glob.glob(os.path.join(patch_dir, "*.patch"))
    if not patch_files:
        print(f"No .patch files found in {patch_dir}")
        return
    
    print(f"\nFound {len(patch_files)} patch files to process.")
    print("-" * 70)
    
    # Process each patch sequentially
    success_count = 0
    fail_count = 0
    skip_count = 0
    
    for i, patch_path in enumerate(patch_files, 1):
        patch_filename = os.path.basename(patch_path)
        rule_filename = patch_filename.replace(".patch", ".yaml")
        rule_output_path = os.path.join(rules_output_dir, rule_filename)
        
        # Skip if rule already exists for this patch
        if os.path.exists(rule_output_path):
            print(f"[{i}/{len(patch_files)}] SKIP (already exists): {patch_filename}")
            skip_count += 1
            continue
        
        print(f"\n[{i}/{len(patch_files)}] Processing: {patch_filename}")
        
        # Find cached repo path
        repo_path = _find_cached_repo_path(patch_filename, git_cache_dir)
        if repo_path:
            print(f"  Found cached repo: {repo_path}")
        else:
            print(f"  No cached repo found (semgrep scan will be skipped)")
        
        # Build command
        cmd = [
            "python3", "main.py", "generate",
            "--patch-file", patch_path,
            "--output-dir", rules_output_dir,
        ]
        if repo_path:
            cmd.extend(["--repo-path", repo_path])
        
        try:
            result = subprocess.run(
                cmd,
                cwd=agent_dir,
                timeout=600,  # 10 minute timeout per patch
                capture_output=True,
                text=True,
            )
            
            if result.returncode == 0:
                print(f"  ✓ Rule generated successfully")
                success_count += 1
            else:
                print(f"  ✗ Agent failed (exit code {result.returncode})")
                if result.stderr:
                    # Print last few lines of stderr for debugging
                    stderr_lines = result.stderr.strip().split('\n')
                    for line in stderr_lines[-5:]:
                        print(f"    {line}")
                fail_count += 1
                
        except subprocess.TimeoutExpired:
            print(f"  ✗ Timeout (>10 minutes)")
            fail_count += 1
        except Exception as e:
            print(f"  ✗ Error: {e}")
            fail_count += 1
    
    # Summary
    print("\n" + "=" * 70)
    print(f"Rule Generation Summary:")
    print(f"  Total patches: {len(patch_files)}")
    print(f"  Successful: {success_count}")
    print(f"  Failed: {fail_count}")
    print(f"  Skipped (existing): {skip_count}")
    print("=" * 70)
    
    # Count generated rules
    generated_rules = glob.glob(os.path.join(rules_output_dir, "*.yaml"))
    
    if generated_rules:
        print(f"\n{len(generated_rules)} rules in {rules_output_dir}")
        
        # Push to git
        from Code.push_rules_to_git import push_rules_to_git
        push_success = push_rules_to_git(rules_output_dir, weekly_folder_name)
        
        if push_success:
            print("✓ Rules pushed to ts-rules repository.")
            
            # Cleanup: remove local rules after successful push
            import shutil
            print(f"Cleaning up local rules: {rules_output_dir}")
            shutil.rmtree(rules_output_dir, ignore_errors=True)
            
            # Cleanup: remove cloned repos
            if os.path.exists(git_cache_dir):
                print(f"Cleaning up cached repos: {git_cache_dir}")
                shutil.rmtree(git_cache_dir, ignore_errors=True)
            
            print("✓ Cleanup complete.")
        else:
            print("⚠ Git push failed. Local rules preserved for retry.")
    else:
        print("No rules generated. Skipping git push.")


def app():
    run_semgrep_rule_generation()


if __name__ == "__main__":
    app()