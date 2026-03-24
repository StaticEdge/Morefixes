import os
import time
import glob
import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
import requests
from datetime import datetime, timedelta
import json

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

if __name__ == "__main__":
    fetch_latest_cves()