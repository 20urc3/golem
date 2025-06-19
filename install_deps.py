import os
import sys
import platform
import shutil
import subprocess
import tempfile
import urllib.request

LLVM_VERSION = '18'
GRAPHVIZ_CMD = 'dot'


def is_installed(cmd):
    return shutil.which(cmd) is not None


def run_command(cmd, check=True):
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=check)


def install_linux():
    # Detect distro codename
    try:
        codename = subprocess.check_output(['lsb_release', '-cs'], text=True).strip()
    except Exception:
        print("Could not detect Linux distribution codename. Defaulting to 'focal'.")
        codename = 'focal'

    # Add LLVM apt repo
    repo_line = f"deb http://apt.llvm.org/{codename}/ llvm-toolchain-{codename}-{LLVM_VERSION} main"
    print(f"Adding LLVM APT repository: {repo_line}")
    run_command(['wget', '-O', '-', 'https://apt.llvm.org/llvm-snapshot.gpg.key'], check=True)
    run_command(['sudo', 'apt-key', 'add', '-'], check=True)
    with open(f"/etc/apt/sources.list.d/llvm-{LLVM_VERSION}.list", 'w') as f:
        f.write(repo_line + '\n')

    # Update and install
    run_command(['sudo', 'apt-get', 'update'])
    run_command(['sudo', 'apt-get', 'install', '-y', f'llvm-{LLVM_VERSION}', 'graphviz'])


def install_mac():
    # Use Homebrew
    run_command(['brew', 'update'])
    run_command(['brew', 'install', f'llvm@{LLVM_VERSION}', 'graphviz'])
    print('Note: brew may suggest adding llvm to your PATH via:')
    print(f'  echo "export PATH=/usr/local/opt/llvm@{LLVM_VERSION}/bin:$PATH" >> ~/.bash_profile')


def download_and_run(url, silent_args=None):
    if silent_args is None:
        silent_args = []
    print(f"Downloading installer from {url}")
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(url)[1])
    urllib.request.urlretrieve(url, tmp.name)
    cmd = [tmp.name] + silent_args
    run_command(cmd)
    os.unlink(tmp.name)


def install_windows():
    # LLVM installer
    llvm_url = f'https://github.com/llvm/llvm-project/releases/download/llvmorg-{LLVM_VERSION}.0.0/LLVM-{LLVM_VERSION}.0.0-win64.exe'
    # Graphviz installer
    gv_url = 'https://graphviz.gitlab.io/_pages/Download/Download_windows.html'
    
    # Silent install flags may vary; user may need to adjust
    download_and_run(llvm_url, ['/S'])
    print('Please download and install Graphviz manually from:')
    print(gv_url)


def main():
    # Check LLVM
    llvm_cmd = f'llvm-config-{LLVM_VERSION}'
    if not is_installed(llvm_cmd) and not is_installed('llvm-config'):
        print(f'LLVM {LLVM_VERSION} not found.')
        installer = platform.system()
        if installer == 'Linux':
            install_linux()
        elif installer == 'Darwin':
            install_mac()
        elif installer == 'Windows':
            install_windows()
        else:
            print(f'Unsupported platform: {installer}')
            sys.exit(1)
    else:
        print(f'LLVM {LLVM_VERSION} is already installed.')

    # Check Graphviz
    if not is_installed(GRAPHVIZ_CMD):
        print('Graphviz not found.')
        installer = platform.system()
        if installer == 'Linux':
            run_command(['sudo', 'apt-get', 'install', '-y', 'graphviz'])
        elif installer == 'Darwin':
            run_command(['brew', 'install', 'graphviz'])
        elif installer == 'Windows':
            print('Please download and install Graphviz manually: https://graphviz.org/download/')
        else:
            print(f'Unsupported platform: {installer}')
            sys.exit(1)
    else:
        print('Graphviz is already installed.')

    print('Dependency check and installation complete.')

if __name__ == '__main__':
    main()
