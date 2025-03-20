import subprocess
import os
import sys


def run_command(cmd):
    print(f"Running: {cmd}")
    result = subprocess.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"Command failed with return code {result.returncode}.")
        sys.exit(result.returncode)

def main():
    if not os.path.exists("venv"):
        run_command("python3 -m venv venv")
    else:
        print("Virtual environment 'venv' already exists.")

    pip_path = "venv/bin/pip" if os.name != "nt" else "venv\\Scripts\\pip.exe"

    run_command(f"{pip_path} install -r requirements.txt")

    run_command("touch sps_tickets_in_progress.json")
    run_command("touch sps_processed_tickets.json")
    run_command("touch etp_tickets_in_progress.json")
    run_command("touch etp_processed_tickets.json")
    run_command("touch open_sps_summary_tickets.csv")
    run_command("touch open_etp_summary_tickets.csv")
    run_command("touch sps_intel_update_file.csv")
    
    print("Environment setup complete!")
    print("To activate the virtual environment, run:")
    if os.name != "nt":
        print("  source venv/bin/activate")
    else:
        print("  venv\\Scripts\\activate")

if __name__ == '__main__':
    main()
