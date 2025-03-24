import subprocess
import os
import sys
from config import logger
import re


class GitRepoManager:
    def __init__(self, repo_path):
        self.repo_path = repo_path

    def run_command(self, command):
        result = subprocess.run(command, cwd=self.repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            logger.error(f"Github error: {' '.join(command)}\n{result.stderr}")
            raise Exception(f"Command failed: {' '.join(command)}\n{result.stderr}")
        
        self.result = result.stdout.strip()
        self.std_err = result.stderr.strip()

    def checkout_master(self):
        self.run_command(["git", "checkout", "master"])
    
    def git_pull(self):
        self.run_command(["git", "pull"])

    def create_new_branch(self, branch_name):
        self.run_command(["git", "checkout", "-b", branch_name])

    def update_file(self, new_content):
        with open(self.file_to_modify, "a") as f:
            f.writelines([line + "\n" for line in new_content])

    def git_add(self, files):
        self.run_command(["git", "add"] + files)

    def git_commit(self, commit_message):
        self.run_command(["git", "commit", "-m", commit_message])
    
    def push_changes(self, branch_name):
        # git_url = f"ssh://git@git.source.akamai.com:7999/~{user_name}/etp-threat-intel-config.git"
        self.run_command(["git", "push", "--set-upstream", "origin", branch_name])
        self.push_link = self.result

    def get_pr_link(self):
        match = re.search(r"https://git\.source\.akamai\.com[^\s]+", self.std_err)
        self.pr_link = match.group(0) if match else None
        if self.pr_link: 
            self.pr_comment = f"Create Pull Request: \n{self.pr_link}"
        else:
            self.pr_comment = f"Git Push Failed... \nPlease update intel manually"

    def start_ssh_agent(self):
        try:
            ssh_agent_output = subprocess.run(
                ["ssh-agent", "-s"],
                capture_output=True,
                text=True,
                check=True,
            )

            agent_vars = {}
            for line in ssh_agent_output.stdout.splitlines():
                if '=' in line:
                    key, value = line.split('=', 1)
                    agent_vars[key.strip()] = value.strip(';')
            
            for key, value in agent_vars.items():
                if key in ["SSH_AUTH_SOCK", "SSH_AGENT_PID"]:
                    os.environ[key] = value
        
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.stderr if e.stderr else str(e)}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def add_ssh_key(self, ssh_key):
        try:
            subprocess.run(
                ["ssh-add", ssh_key],
                check=True
            )
        
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.stderr if e.stderr else str(e)}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)

    def change_directory(self, path):
        try:
            os.chdir(path)
            print(f"Successfully changed directory to {path}.")
        except FileNotFoundError:
            print(f"Error: Directory {path} does not exist.", file=sys.stderr)
            sys.exit(1)
        except PermissionError:
            print(f"Error: Permission denied for directory {path}.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Unexpected error: {str(e)}", file=sys.stderr)
            sys.exit(1)
