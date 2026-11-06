"""Install tool dependencies into the running Python and project environment."""
import os
from pathlib import Path
import subprocess
import sys

from . import terminal as ui

ROOT = Path(__file__).resolve().parents[1]


def environment_python():
    return ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')


def install_requirements():
    python = environment_python()
    print(ui.rule('Install requirements'))
    print(ui.message(f'Environment: {python.parent.parent}'))
    try:
        if not python.is_file():
            print(ui.message('Creating the project environment...'))
            sys.stdout.flush()
            result = subprocess.run([sys.executable, '-m', 'venv', str(ROOT / '.venv')], cwd=ROOT)
            if result.returncode:
                print(ui.message('Environment creation failed. Check the error above and retry.', 'error'))
                return result.returncode
        targets = [Path(sys.executable)]
        if os.path.normcase(str(python.resolve())) != os.path.normcase(str(Path(sys.executable).resolve())):
            targets.append(python)
        for target in targets:
            print(ui.message(f'Installing with: {target} -m pip install -r requirements.txt'))
            sys.stdout.flush()
            result = subprocess.run([str(target), '-m', 'pip', 'install', '-r', 'requirements.txt'], cwd=ROOT)
            if result.returncode:
                print(ui.message('Installation failed. Check pip output above, fix the issue, and press I to retry.', 'error'))
                return result.returncode
        for target in targets:
            result = subprocess.run([str(target), '-m', 'pip', 'check'], cwd=ROOT)
            if result.returncode:
                print(ui.message(f'Packages installed, but pip found conflicts in {target}. Review the output above.', 'error'))
                return result.returncode
        print(ui.message('All requirements installed. Dependency check passed.', 'success'))
        return 0
    except OSError as error:
        print(ui.message(f'Could not run the installer: {error}', 'error'))
        return 1
