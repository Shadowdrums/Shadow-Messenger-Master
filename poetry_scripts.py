import subprocess
import os
from shadowmessenger.master import main as run_main

def install():
    """Install project dependencies."""
    subprocess.run(["poetry", "install"], check=True)
    print("Dependencies installed.")

def build():
    """Build the project."""
    subprocess.run(["poetry", "build"], check=True)
    print("Project built.")

def test():
    """Run tests."""
    subprocess.run(["poetry", "run", "pytest"], check=True)
    print("Tests completed.")

def clean():
    """Clean up the project."""
    db_path = "user_data.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Removed database file: {db_path}")
    else:
        print(f"Database file does not exist: {db_path}")

    # Additional cleanup tasks can be added here
    print("Cleanup complete.")

def refresh():
    """Refresh the git repository."""
    subprocess.run(["git", "fetch"], check=True)
    subprocess.run(["git", "pull"], check=True)
    print("Repository refreshed.")

def run():
    """Install dependencies and run the application."""
    install()
    run_main()

def banner():
    try:
        with open(".banner") as fp:
            print(fp.read())
    except FileNotFoundError:
        pass

if __name__ == "__main__":
    banner()
    import sys
    script_name = sys.argv[1] if len(sys.argv) > 1 else None
    if script_name == "install":
        install()
    elif script_name == "build":
        build()
    elif script_name == "test":
        test()
    elif script_name == "clean":
        clean()
    elif script_name == "refresh":
        refresh()
    elif script_name == "run":
        run()
    else:
        print("Unknown script name. Please use 'install', 'build', 'test', 'clean', 'refresh', or 'run'.")
