"""
Git push utility for pushing generated Semgrep rules to the ts-rules repository.

Clones/pulls the ts-rules repo, copies the weekly rules folder,
commits, and pushes via SSH.
"""

import os
import shutil
import subprocess
from pathlib import Path


TS_RULES_REPO_URL = "git@github.com:StaticEdge/ts-rules.git"
TS_RULES_LOCAL_DIR = "ts-rules"  # Will be inside tmp/


def push_rules_to_git(rules_dir: str, weekly_folder_name: str) -> bool:
    """
    Push generated rules to the ts-rules GitHub repository.
    
    1. Clone/pull the ts-rules repo into tmp/ts-rules/
    2. Copy the weekly rules folder into the repo
    3. git add, commit, push
    4. Clean up the local ts-rules clone
    
    Args:
        rules_dir: Path to the directory containing generated rule YAML files.
        weekly_folder_name: Name of the weekly folder (e.g., '2026-W15').
    
    Returns:
        True if push was successful, False otherwise.
    """
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmp_dir = os.path.join(project_root, "tmp")
    repo_dir = os.path.join(tmp_dir, TS_RULES_LOCAL_DIR)
    
    os.makedirs(tmp_dir, exist_ok=True)
    
    print(f"\n--- Pushing rules to {TS_RULES_REPO_URL} ---")
    
    try:
        # 1. Clone or pull the repo
        if os.path.exists(repo_dir):
            print(f"  Pulling latest from ts-rules...")
            result = subprocess.run(
                ["git", "pull", "--rebase"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                timeout=120
            )
            if result.returncode != 0:
                print(f"  Warning: git pull failed, re-cloning...")
                shutil.rmtree(repo_dir, ignore_errors=True)
                _clone_repo(repo_dir)
        else:
            _clone_repo(repo_dir)
        
        # 2. Copy weekly folder into the repo
        dest_folder = os.path.join(repo_dir, weekly_folder_name)
        os.makedirs(dest_folder, exist_ok=True)
        
        rule_files = list(Path(rules_dir).glob("*.yaml"))
        if not rule_files:
            print("  No rule files to push.")
            return False
        
        copied_count = 0
        for rule_file in rule_files:
            dest_file = os.path.join(dest_folder, rule_file.name)
            shutil.copy2(str(rule_file), dest_file)
            copied_count += 1
        
        print(f"  Copied {copied_count} rule(s) to {weekly_folder_name}/")
        
        # 3. Git add, commit, push
        # Stage all changes
        subprocess.run(
            ["git", "add", "."],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=30
        )
        
        # Check if there are changes to commit
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if not status_result.stdout.strip():
            print("  No new changes to commit (rules already up-to-date).")
            return True
        
        # Commit
        from datetime import datetime
        commit_msg = f"Add {copied_count} rule(s) for {weekly_folder_name} — {datetime.now().strftime('%Y-%m-%d %H:%M')}"
        
        subprocess.run(
            ["git", "commit", "-m", commit_msg],
            cwd=repo_dir,
            check=True,
            capture_output=True,
            timeout=30
        )
        print(f"  Committed: {commit_msg}")
        
        # Push
        print("  Pushing to remote...")
        push_result = subprocess.run(
            ["git", "push"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if push_result.returncode == 0:
            print("  ✓ Successfully pushed to ts-rules!")
            # Clean up local ts-rules clone
            shutil.rmtree(repo_dir, ignore_errors=True)
            return True
        else:
            print(f"  ✗ Push failed: {push_result.stderr}")
            return False
        
    except subprocess.TimeoutExpired:
        print("  ✗ Git operation timed out.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"  ✗ Git error: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Unexpected error: {e}")
        return False


def _clone_repo(repo_dir: str):
    """Clone the ts-rules repository."""
    print(f"  Cloning ts-rules repo...")
    subprocess.run(
        ["git", "clone", TS_RULES_REPO_URL, repo_dir],
        check=True,
        capture_output=True,
        timeout=120
    )
    print(f"  ✓ Cloned to {repo_dir}")
