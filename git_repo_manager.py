import subprocess
import os
import sys
import re


class GitRepoManager:
    def __init__(self, logger, repo_path):
        self.logger = logger
        self.repo_path = repo_path

    def run_command(self, command):
        result = subprocess.run(command, cwd=self.repo_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            self.logger.error(f"Github error: {' '.join(command)}\n{result.stderr}")
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
        self.logger.info(f"Adding files to git")
        self.run_command(["git", "add"] + files)

    def git_commit(self, commit_message):
        self.logger.info(f"Commiting files")
        self.run_command(["git", "commit", "-m", commit_message])
    
    def push_changes(self, branch_name):
        self.run_command(["git", "push", "--set-upstream", "origin", branch_name])
        self.push_link = self.result

    def get_pr_link(self):
        match = re.search(r"https://git\.source\.akamai\.com[^\s]+", self.std_err)
        self.pr_link = match.group(0) if match else None
        if self.pr_link: 
            self.logger.info(f"PR link: {self.pr_link}")
            self.pr_comment = f"Create Pull Request: \n{self.pr_link}"
        else:
            self.logger.info(f"Git Push Failed, no PR link")
            self.pr_comment = f"Git Push Failed... \nPlease update intel manually"

    def start_ssh_agent(self):
        try:
            ssh_agent_output = subprocess.run(
                ["ssh-agent", "-s"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.logger.info("SSH agent started.")

            agent_vars = {}
            for line in ssh_agent_output.stdout.splitlines():
                if '=' in line:
                    clean_line = line.split(';')[0].strip()  # Remove any trailing '; export ...'
                    key, value = clean_line.split('=', 1)
                    agent_vars[key.strip()] = value.strip()


            for key in ["SSH_AUTH_SOCK", "SSH_AGENT_PID"]:
                if key in agent_vars:
                    os.environ[key] = agent_vars[key]
                    self.logger.info(f"{key}: {agent_vars[key]}")
                else:
                    self.logger.warning(f"{key} not found in ssh-agent output.")

            self.logger.info("SSH agent started successfully.")
            self.logger.info(f'SSH_AUTH_SOCK: {os.environ.get("SSH_AUTH_SOCK")}')
            self.logger.info(f'SSH_AGENT_PID: {os.environ.get("SSH_AGENT_PID")}')
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error: {e.stderr if e.stderr else str(e)}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            sys.exit(1)

    def add_ssh_key(self, ssh_key):
        try:
            subprocess.run(
                ["ssh-add", ssh_key],
                check=True
            )
        
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error: {e.stderr if e.stderr else str(e)}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            sys.exit(1)

    def change_directory(self, path):
        try:
            os.chdir(path)
            self.logger.info(f"Successfully changed directory to {path}.")
        except FileNotFoundError:
            self.logger.error(f"Error: Directory {path} does not exist.")
            sys.exit(1)
        except PermissionError:
            self.logger.error(f"Error: Permission denied for directory {path}.")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            sys.exit(1)

    def kill_ssh_agent(self):
        subprocess.run(["ssh-agent", "-k"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)