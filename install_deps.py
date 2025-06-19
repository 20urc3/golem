import os
import sys
import platform
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

LLVM_VERSION = '18'
GRAPHVIZ_CMD = 'dot'
OLLAMA_LINUX_URL = 'https://ollama.com/install.sh'
OLLAMA_WINDOWS_URL = 'https://ollama.com/download/OllamaSetup.exe'
OLLAMA_MAC_URL = 'https://ollama.com/download/Ollama-darwin.zip'


def is_installed(cmd):
    return shutil.which(cmd) is not None


def run_command(cmd, check=True):
    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=check)


def download_file(url, suffix=None):
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix or os.path.splitext(url)[1])
    print(f"Downloading from {url} to {tmp.name}")
    urllib.request.urlretrieve(url, tmp.name)
    return tmp.name


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
    run_command(['wget', '-O', '-', 'https://apt.llvm.org/llvm-snapshot.gpg.key'])
    run_command(['sudo', 'apt-key', 'add', '-'])
    with open(f"/etc/apt/sources.list.d/llvm-{LLVM_VERSION}.list", 'w') as f:
        f.write(repo_line + '\n')

    # Update and install
    run_command(['sudo', 'apt-get', 'update'])
    run_command(['sudo', 'apt-get', 'install', '-y', f'llvm-{LLVM_VERSION}', 'graphviz'])


def install_mac():
    # Use Homebrew for LLVM and Graphviz
    run_command(['brew', 'update'])
    run_command(['brew', 'install', f'llvm@{LLVM_VERSION}', 'graphviz'])
    print('Note: brew may suggest adding llvm to your PATH via:')
    print(f'  echo "export PATH=/usr/local/opt/llvm@{LLVM_VERSION}/bin:$PATH" >> ~/.bash_profile')


def install_ollama_linux():
    # Install Ollama via shell script
    run_command(['sh', '-c', f"curl -fsSL {OLLAMA_LINUX_URL} | sh"])


def install_ollama_mac():
    # Download and extract Ollama
    zip_path = download_file(OLLAMA_MAC_URL, suffix='.zip')
    dest_dir = '/usr/local/bin'
    print(f"Extracting Ollama to {dest_dir}")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(dest_dir)
    os.unlink(zip_path)


def install_windows():
    # LLVM installer
    llvm_url = f'https://github.com/llvm/llvm-project/releases/download/llvmorg-{LLVM_VERSION}.0.0/LLVM-{LLVM_VERSION}.0.0-win64.exe'
    gv_url = 'https://graphviz.gitlab.io/_pages/Download/Download_windows.html'

    download_file(llvm_url)
    print('Please download and install Graphviz manually from:')
    print(gv_url)


def install_ollama_windows():
    # Download and silently install Ollama
    setup_path = download_file(OLLAMA_WINDOWS_URL)
    run_command([setup_path, '/S'])
    os.unlink(setup_path)


def main():
    # LLVM check
    llvm_cmd = f'llvm-config-{LLVM_VERSION}'
    if not is_installed(llvm_cmd) and not is_installed('llvm-config'):
        print(f'LLVM {LLVM_VERSION} not found.')
        system = platform.system()
        if system == 'Linux':
            install_linux()
        elif system == 'Darwin':
            install_mac()
        elif system == 'Windows':
            install_windows()
        else:
            print(f'Unsupported platform: {system}')
            sys.exit(1)
    else:
        print(f'LLVM {LLVM_VERSION} is already installed.')

    # Graphviz check
    if not is_installed(GRAPHVIZ_CMD):
        print('Graphviz not found.')
        system = platform.system()
        if system == 'Linux':
            run_command(['sudo', 'apt-get', 'install', '-y', 'graphviz'])
        elif system == 'Darwin':
            run_command(['brew', 'install', 'graphviz'])
        elif system == 'Windows':
            print('Please download and install Graphviz manually: https://graphviz.org/download/')
        else:
            print(f'Unsupported platform: {system}')
            sys.exit(1)
    else:
        print('Graphviz is already installed.')

    # Ollama check
    if not is_installed('ollama'):
        print('Ollama not found.')
        system = platform.system()
        if system == 'Linux':
            install_ollama_linux()
        elif system == 'Darwin':
            install_ollama_mac()
        elif system == 'Windows':
            install_ollama_windows()
        else:
            print(f'Unsupported platform: {system}')
            sys.exit(1)
    else:
        print('Ollama is already installed.')

    print('Dependency check and installation complete.')


if __name__ == '__main__':
    main()
