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
    script_dir = os.path.dirname(os.path.abspath(__file__))
    venv_path = os.path.join(script_dir, "venv")

    if not os.path.exists(venv_path):
        run_command(f"python3 -m venv {venv_path}")
    else:
        print("Virtual environment 'venv' already exists.")

    pip_path = (
        os.path.join(venv_path, "bin", "pip")
        if os.name != "nt"
        else os.path.join(venv_path, "Scripts", "pip.exe")
    )

    run_command(f"{pip_path} install -r {os.path.join(script_dir, 'requirements.txt')}")

    run_command(f"touch {os.path.join(script_dir, 'sps_tickets_in_progress.json')}")
    run_command(f"touch {os.path.join(script_dir, 'sps_processed_tickets.json')}")
    run_command(f"touch {os.path.join(script_dir, 'etp_tickets_in_progress.json')}")
    run_command(f"touch {os.path.join(script_dir, 'etp_processed_tickets.json')}")
    run_command(f"touch {os.path.join(script_dir, 'open_sps_summary_tickets.csv')}")
    run_command(f"touch {os.path.join(script_dir, 'open_etp_summary_tickets.csv')}")
    run_command(f"touch {os.path.join(script_dir, 'sps_intel_update_file.csv')}")

    print("Environment setup complete!")
    print("To activate the virtual environment, run:")
    if os.name != "nt":
        print("  source venv/bin/activate")
    else:
        print("  venv\\Scripts\\activate")


if __name__ == "__main__":
    main()
