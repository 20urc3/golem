#!/usr/bin/env python3
import os
import json
import subprocess
import glob
import argparse
import re
import shutil
import zipfile
import openai
import requests
import chromadb
import sys
from pathlib import Path
from typing import Set, List, Dict
import pydot
import time
import signal
import psutil

SEMgrep_RULES_DIR = Path(os.getcwd()) / 'semgrep-rules'
CALLGRAPH_CMD = 'opt -passes="dot-callgraph"'
CFG_CMD = 'opt -passes="dot-cfg"'
SLICE_DEPTH = 3
SEMgrep_OUTPUT = 'result_scan.json'
ALLOWED_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp'}
FUNC_DEF_REGEX = re.compile(r'^\s*[\w\*\s]+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{')

prompt = '''
## Semgrep Findings

| # | File | Line | Function | Semgrep Rule |
|---|------|------|----------|--------------|
{% for idx, entry in enumerate(findings, 1) %}
| {{idx}} | {{entry['finding']['file']}} | {{entry['finding']['line']}} | {{entry['function']}} | {{entry['finding']['rule_id'] or 'N/A'}} |
{% endfor %}

## Graph Artifacts

{% for entry in findings %}
### Finding {{loop.index}}
**Call Graph:**
```
{{ read_file(callgraph_dir / entry['callgraph']) }}
```
**CFG Slice:**
```
{{ read_file(slices_dir / entry['cfg_slice']) }}
```
{% endfor %}

## Analysis Task
You are a security auditor assistant. For the above Semgrep findings and graph artifacts:

1. **Executive Summary**
   - Summarize the overall security analysis process and outcomes.
2. **Per-Finding Decision Table**

| # | Function | Reachable? | Sanitized? | Verdict |
|---|----------|------------|------------|---------|
{% for idx, entry in enumerate(findings, 1) %}
| {{idx}} | {{entry['function']}} |  |  |  |
{% endfor %}

- **Reachable?**: Can untrusted input reach the sink?  
- **Sanitized?**: Is there any sanitization or guard?  
- **Verdict**: True Positive, False Positive, or Manual Review.

3. **Conclusion**
   - Provide overall risk severity and next steps recommendations.
'''

def run_semgrep(project_dir: Path, report_dir: Path) -> bool:
    print(f"[+] Now scanning for vulnerabilities with Semgrep in '{project_dir}'...")
    output_path = report_dir / SEMgrep_OUTPUT
    proc = subprocess.run(
        ['semgrep', '--config', str(SEMgrep_RULES_DIR), f'--json-output={output_path}', str(project_dir)],
        cwd=project_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print("[+] Semgrep scan done!")
    return proc.returncode == 0


def load_semgrep_results(path: Path) -> list:
    data = json.loads(path.read_text())
    findings = []
    for res in data.get('results', []):
        p = res.get('path'); src = p.get('repr') if isinstance(p, dict) else p
        if not src or Path(src).suffix.lower() not in ALLOWED_EXTENSIONS: continue
        findings.append({
            'finding': {'file': src, 'line': res['start']['line'], 'rule_id': res.get('check_id')},
            'function': res.get('extra', {}).get('metadata', {}).get('function')
        })
    return findings


def infer_function_name(source_file: Path, line_no: int) -> str | None:
    name = None
    for idx, line in enumerate(source_file.read_text().splitlines(), start=1):
        if idx > line_no: break
        m = FUNC_DEF_REGEX.match(line)
        if m: name = m.group('name')
    return name


def find_ll_file(source_path: str, root: Path) -> Path | None:
    base = Path(source_path).stem
    matches = list(root.rglob(f"{base}.ll"))
    return matches[0] if matches else None


def generate_graphs(ll_file: Path, callgraph_dir: Path, cfg_dir: Path) -> Path:
    print("[+] Generating LLVM callgraph and CFG slices...")
    stem = ll_file.stem
    cg_dot = callgraph_dir / f"{stem}.ll.callgraph.dot"
    subprocess.run(
        f"{CALLGRAPH_CMD} {ll_file} -o {cg_dot}",
        cwd=callgraph_dir,
        shell=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    subprocess.run(
        f"{CFG_CMD} {ll_file}",
        cwd=cfg_dir,
        shell=True,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    print("[+] CFG and callgraph generation done!")
    return cg_dot


def slice_cfg(cfg_path: Path, target_line: int, depth: int = SLICE_DEPTH) -> str | None:
    graphs = pydot.graph_from_dot_file(str(cfg_path)) or []
    if not graphs: return None
    graph = graphs[0]
    nodes = [n for n in graph.get_nodes() if f":{target_line}" in n.get_attributes().get('label','')]
    if not nodes: return None
    slice_nodes = set(nodes); frontier = set(nodes)
    for _ in range(depth):
        next_front = set()
        for e in graph.get_edges():
            src, dst = e.get_source(), e.get_destination()
            if any(n.get_name()==dst for n in frontier): next_front.update(n for n in graph.get_nodes() if n.get_name()==src)
            if any(n.get_name()==src for n in frontier): next_front.update(n for n in graph.get_nodes() if n.get_name()==dst)
        slice_nodes |= next_front; frontier = next_front
    sub = pydot.Dot(graph_type='digraph'); names={n.get_name() for n in slice_nodes}
    for n in slice_nodes: sub.add_node(n)
    for e in graph.get_edges():
        if e.get_source() in names and e.get_destination() in names: sub.add_edge(e)
    return sub.to_string()


def copy_source_files(findings: list, project_dir: Path, report_dir: Path) -> None:
    print("[+] Copying source files to report...")
    src_dir = report_dir / 'src'
    src_dir.mkdir(exist_ok=True)
    
    copied_files: Set[str] = set()
    copy_count = 0
    
    for entry in findings:
        src_file = entry['finding']['file']
        if src_file in copied_files:
            continue
            
        copied_files.add(src_file)
        
        source_path = project_dir / src_file
        if source_path.exists():
            relative_path = Path(src_file)
            dest_path = src_dir / relative_path.name
            
            try:
                shutil.copy2(source_path, dest_path)
                copy_count += 1
                print(f"  Copied: {src_file}")
            except Exception as e:
                print(f"  Error copying {src_file}: {e}")
        else:
            print(f"  Source file not found: {src_file}")
                    
    print(f"[+] Copied {copy_count} source files")


def create_report_zip(report_dir: Path) -> Path:
    print("[+] Creating report zip file...")
    zip_path = report_dir.parent / f"{report_dir.name}.zip"
    
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in report_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(report_dir.parent)
                zipf.write(file_path, arcname)
    
    print(f"[+] Report zip created: {zip_path}")
    return zip_path


def setup_chromadb(report_dir: Path) -> chromadb.Collection:
    print("[+] Setting up ChromaDB...")
    chroma_client = chromadb.PersistentClient(path=str(report_dir / "chroma_db"))
    collection = chroma_client.get_or_create_collection(name="security_analysis")
    return collection


def add_to_chromadb(collection: chromadb.Collection, findings: List[Dict], report_dir: Path) -> None:
    print("[+] Adding source code to ChromaDB...")
    documents = []
    metadatas = []
    ids = []
    
    src_dir = report_dir / 'src'
    if not src_dir.exists():
        return
    
    for idx, entry in enumerate(findings):
        src_file = src_dir / Path(entry['finding']['file']).name
        if src_file.exists():
            try:
                content = src_file.read_text()
                documents.append(content)
                metadatas.append({
                    "file": entry['finding']['file'],
                    "line": entry['finding']['line'],
                    "function": entry.get('function', 'N/A'),
                    "rule_id": entry['finding'].get('rule_id', 'N/A')
                })
                ids.append(f"finding_{idx}")
            except Exception as e:
                print(f"  Error reading {src_file}: {e}")
    
    if documents:
        collection.add(
            documents=documents,
            metadatas=metadatas,
            ids=ids
        )
        print(f"[+] Added {len(documents)} documents to ChromaDB")


def query_chromadb(collection: chromadb.Collection, query: str, n_results: int = 5) -> List[Dict]:
    results = collection.query(
        query_texts=[query],
        n_results=n_results
    )
    return results

def is_ollama_running() -> bool:
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=5)
        return response.status_code == 200
    except:
        return False

def start_ollama() -> subprocess.Popen:
    print("[+] Starting Ollama server...")
    process = subprocess.Popen(
        ['ollama', 'serve'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    
    for i in range(30):
        if is_ollama_running():
            print("[+] Ollama server started successfully!")
            return process
        time.sleep(1)
        print(f"[+] Waiting for Ollama to start... ({i+1}/30)")
    
    raise Exception("Ollama failed to start within 30 seconds")

def stop_ollama(process: subprocess.Popen):
    if process and process.poll() is None:
        print("[+] Stopping Ollama server...")
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        process.wait(timeout=10)

def ensure_model_available(model: str):
    print(f"[+] Checking if model '{model}' is available...")
    try:
        response = requests.get("http://localhost:11434/api/tags", timeout=10)
        if response.status_code == 200:
            models = response.json().get('models', [])
            available_models = [m['name'] for m in models]
            if model not in available_models:
                print(f"[+] Model '{model}' not found. Pulling...")
                pull_process = subprocess.run(
                    ['ollama', 'pull', model],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                if pull_process.returncode != 0:
                    raise Exception(f"Failed to pull model: {pull_process.stderr}")
                print(f"[+] Model '{model}' pulled successfully!")
            else:
                print(f"[+] Model '{model}' is already available!")
    except Exception as e:
        raise Exception(f"Failed to ensure model availability: {e}")

def send_to_ollama(report_dir: Path, findings: List[Dict], model: str = "llama3.1") -> str:
    ollama_process = None
    try:
        if not is_ollama_running():
            ollama_process = start_ollama()
        
        ensure_model_available(model)
        
        print(f"[+] Sending analysis to Ollama ({model})...")
        
        collection = setup_chromadb(report_dir)
        add_to_chromadb(collection, findings, report_dir)
        
        analysis_content = prepare_rag_analysis(report_dir, findings, collection)
        
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": analysis_content,
                "stream": False
            },
            headers={"Content-Type": "application/json"},
            timeout=300
        )
        
        if response.status_code != 200:
            raise Exception(f"Ollama API returned status {response.status_code}: {response.text}")
        
        result = response.json()
        ollama_analysis = result.get("response", "")
        
        if not ollama_analysis:
            raise Exception("Empty response from Ollama")
        
        ollama_report_path = report_dir / 'ollama_analysis.md'
        ollama_report_path.write_text(ollama_analysis)
        
        print("[+] Ollama analysis complete and saved to ollama_analysis.md")
        return str(ollama_report_path)
        
    except Exception as e:
        print(f"\x1b[91m[ERROR] Failed to get Ollama analysis: {e}\x1b[0m")
        raise
    finally:
        if ollama_process:
            stop_ollama(ollama_process)

def prepare_rag_analysis(report_dir: Path, findings: List[Dict], collection: chromadb.Collection) -> str:
    content = """You are a security auditor assistant. Analyze the provided Semgrep findings using the context from the codebase.

# Security Analysis Report

## Semgrep Findings

| # | File | Line | Function | Semgrep Rule |
|---|------|------|----------|--------------|
"""
    
    for idx, entry in enumerate(findings, 1):
        file_name = entry['finding']['file']
        line = entry['finding']['line']
        function = entry.get('function', 'N/A')
        rule_id = entry['finding'].get('rule_id', 'N/A')
        content += f"| {idx} | {file_name} | {line} | {function} | {rule_id} |\n"
    
    content += "\n## Code Context Analysis\n\n"
    
    for idx, entry in enumerate(findings, 1):
        content += f"### Finding {idx}: {entry['finding']['file']} (Line {entry['finding']['line']})\n\n"
        
        query = f"vulnerability {entry['finding'].get('rule_id', '')} {entry.get('function', '')} security"
        rag_results = query_chromadb(collection, query, n_results=3)
        
        if rag_results['documents']:
            content += "**Related Code Context:**\n"
            for doc_idx, doc in enumerate(rag_results['documents'][0][:2]):
                metadata = rag_results['metadatas'][0][doc_idx]
                content += f"\n*From {metadata['file']}:*\n"
                content += f"```c\n{doc[:500]}...\n```\n"
        
        content += "\n"
    
    content += """## Analysis Task

For each finding above, analyze the security implications using the provided code context:

1. **Executive Summary**
   - Summarize the overall security analysis process and outcomes.

2. **Per-Finding Analysis**

For each finding, provide:
- **Reachability**: Can untrusted input reach this vulnerability?
- **Sanitization**: Are there any input validation or sanitization mechanisms?
- **Exploitability**: How easily can this be exploited?
- **Impact**: What would be the impact if exploited?
- **Verdict**: True Positive, False Positive, or Manual Review needed

3. **Risk Assessment**
   - Provide overall risk severity (Critical/High/Medium/Low)
   - Prioritize findings by exploitability and impact
   - Recommend specific remediation steps

4. **Conclusion and Next Steps**
   - Summary of critical issues that need immediate attention
   - Recommended security improvements
   - Suggested follow-up actions

Please provide a comprehensive analysis based on the code context and security best practices.
"""
    
    return content


def send_to_gpt(report_dir: Path, findings: List[Dict]) -> str:
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    print("[+] Sending analysis to ChatGPT...")
    
    client = openai.OpenAI(api_key=api_key)
    
    analysis_content = prepare_gpt_analysis(report_dir, findings)
    
    try:
        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=[
                {
                    "role": "system",
                    "content": "You are a security auditor assistant. Analyze the provided Semgrep findings and graph artifacts to determine if they are true positives, false positives, or require manual review."
                },
                {
                    "role": "user",
                    "content": analysis_content
                }
            ],
            max_tokens=4000,
            temperature=0.1
        )
        
        gpt_analysis = response.choices[0].message.content
        
        gpt_report_path = report_dir / 'gpt_analysis.md'
        gpt_report_path.write_text(gpt_analysis)
        
        print("[+] GPT analysis complete and saved to gpt_analysis.md")
        return str(gpt_report_path)
        
    except Exception as e:
        print(f"\x1b[91m[ERROR] Failed to get GPT analysis: {e}\x1b[0m")
        raise


def prepare_gpt_analysis(report_dir: Path, findings: list) -> str:
    content = "# Security Analysis Report\n\n"
    
    content += "## Semgrep Findings\n\n"
    content += "| # | File | Line | Function | Semgrep Rule |\n"
    content += "|---|------|------|----------|--------------|\n"
    
    for idx, entry in enumerate(findings, 1):
        file_name = entry['finding']['file']
        line = entry['finding']['line']
        function = entry.get('function', 'N/A')
        rule_id = entry['finding'].get('rule_id', 'N/A')
        content += f"| {idx} | {file_name} | {line} | {function} | {rule_id} |\n"
    
    content += "\n## Source Code Context\n\n"
    
    src_dir = report_dir / 'src'
    if src_dir.exists():
        for entry in findings:
            src_file = src_dir / Path(entry['finding']['file']).name
            if src_file.exists():
                content += f"### {entry['finding']['file']} (Line {entry['finding']['line']})\n\n"
                try:
                    lines = src_file.read_text().splitlines()
                    start_line = max(0, entry['finding']['line'] - 10)
                    end_line = min(len(lines), entry['finding']['line'] + 10)
                    
                    content += "```c\n"
                    for i in range(start_line, end_line):
                        marker = ">>> " if i + 1 == entry['finding']['line'] else "    "
                        content += f"{marker}{i+1:4d}: {lines[i]}\n"
                    content += "```\n\n"
                except Exception as e:
                    content += f"Error reading file: {e}\n\n"
    
    content += """## Analysis Task

For each finding above, please provide:

1. **Executive Summary**
   - Summarize the overall security analysis process and outcomes.

2. **Per-Finding Decision Table**

| # | Function | Reachable? | Sanitized? | Verdict |
|---|----------|------------|------------|---------|
"""
    
    for idx, entry in enumerate(findings, 1):
        function = entry.get('function', 'N/A')
        content += f"| {idx} | {function} |  |  |  |\n"
    
    content += """
- **Reachable?**: Can untrusted input reach the sink?  
- **Sanitized?**: Is there any sanitization or guard?  
- **Verdict**: True Positive, False Positive, or Manual Review.

3. **Conclusion**
   - Provide overall risk severity and next steps recommendations.
"""
    
    return content


def generate_local_report(report_dir: Path, findings: list) -> str:
    print("[+] Generating local markdown report...")
    
    report_content = prepare_gpt_analysis(report_dir, findings)
    
    report_content += """

---

## Manual Analysis Template

Fill in the decision table above and provide your analysis:

### Executive Summary
[Your analysis here]

### Detailed Analysis
[Per-finding analysis here]

### Conclusion
[Overall risk assessment and recommendations]
"""
    
    local_report_path = report_dir / 'security_analysis_template.md'
    local_report_path.write_text(report_content)
    
    print(f"[+] Local report template saved to: {local_report_path}")
    return str(local_report_path)


def main():
    if len(sys.argv) == 1:
        print("\x1b[93mNo super-intelligence (even achieved in-house) passed :( just creating files!\x1b[0m")
        return
    
    parser = argparse.ArgumentParser()
    parser.add_argument('project_dir', type=Path, help='Path to C/C++ project')
    parser.add_argument('--mode', '-m', choices=['local', 'gpt', 'ollama'], default='local', 
                       help='Analysis mode: local (generate template), gpt (send to GPT-4), or ollama (send to Ollama)')
    parser.add_argument('--ollama-model', default='llama3.1', 
                       help='Ollama model to use (default: llama3.1)')
    args = parser.parse_args(); project = args.project_dir.resolve(); cwd = Path.cwd()

    print(r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣡⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢾⠿⢿⣿⣿⣿⣿⡿⠿⡷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡀⣴⡄⢸⣀⣀⣈⣿⣿⣁⣀⣀⡇⢠⣦⣄⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠴⠾⠿⠿⠛⠃⠀⠛⠛⠛⠛⠛⠛⠛⠛⠀⠘⠛⠿⠿⠷⠦⠀⠀⠀⠀
⠀⠀⢀⣤⣤⣴⡆⢀⣶⣾⣿⣿⣷⣦⡀⢀⣴⣾⣿⣿⣷⣶⡀⢰⣦⣤⣤⡀⠀⠀
⠀⢠⣾⣿⣿⣿⠇⢸⣿⣿⣿⣿⣿⣿⡇⢸⣿⣿⣿⣿⣿⣿⡇⠸⣿⣿⣿⣷⡄⠀
⠀⠈⠛⣿⣿⣿⠀⠀⡉⠛⠿⠛⢉⣿⡇⢸⣿⡉⠛⠿⠛⢉⠀⠀⣿⣿⣿⣿⠁⠀
⠀⠀⣾⣿⣿⣿⠀⠀⢿⣷⣶⣿⣿⣿⡇⢸⣿⣿⣿⣄⣼⡿⠀⠀⣿⣿⣿⣿⠀⠀
⠀⠀⠘⢉⣉⣉⠀⠀⠸⣿⣿⣿⣿⣿⡇⢸⣿⣿⣿⣿⣿⠇⠀⠀⣉⣉⡉⠁⠀⠀
⠀⠀⠈⣿⣿⣿⡀⠀⠀⣄⣈⠉⠉⠙⠃⠘⠋⣉⣉⣁⣠⠀⠀⢀⣿⣿⣿⠀⠀⠀
⠀⠀⠀⢹⣿⣿⡇⠀⢠⣿⣿⣧⣾⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⢸⣿⣿⡏⠀⠀⠀
⠀⠀⠀⠘⣿⣿⣇⠀⢸⣿⣿⣿⣿⣿⠏⠹⣿⣿⣿⣿⣿⡇⠀⣸⣿⣿⠃⠀⠀⠀
⠀⠀⠀⠀⠛⠛⠋⠀⣸⣿⣿⣿⣿⠏⠀⠀⠹⣿⣿⡿⣿⣇⠀⠙⠃⠈⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠀⠀⠀⠀⠉⠉⠀⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀
""")
    print(f"\x1b[96mYou unleashed the clay monster 'Golem' upon '{project.name}'!\x1b[0m")

    report_dir = cwd / 'golem_report'
    callgraph_dir = report_dir / 'callgraphs'
    cfg_dir = report_dir / 'cfg'
    slices_dir = report_dir / 'dot_slices'
    report_dir.mkdir(exist_ok=True)
    callgraph_dir.mkdir(exist_ok=True)
    cfg_dir.mkdir(exist_ok=True)
    slices_dir.mkdir(exist_ok=True)

    if not run_semgrep(project, report_dir):
        print("\x1b[91m[ERROR] Semgrep scan failed. Aborting.\x1b[0m")
        return
    print("\x1b[93m[+] Semgrep scan complete. Findings loaded.\x1b[0m")
    findings = load_semgrep_results(report_dir / SEMgrep_OUTPUT)

    copy_source_files(findings, project, report_dir)

    for old in cfg_dir.glob('*.dot'):
        old.unlink()

    summary = []
    processed_ll = set()

    for entry in findings:
        src_file = project / entry['finding']['file']
        func = entry['function'] or infer_function_name(src_file, entry['finding']['line'])
        if not func:
            continue
        entry['function'] = func
        ll = find_ll_file(entry['finding']['file'], project)
        if not ll:
            continue
        if ll not in processed_ll:
            cg = generate_graphs(ll, callgraph_dir, cfg_dir)
            processed_ll.add(ll)
        cfg_candidates = list(cfg_dir.glob(f"*{func}.dot"))
        if not cfg_candidates:
            continue
        cfg = cfg_candidates[0]
        sliced = slice_cfg(cfg, entry['finding']['line'])
        out = slices_dir / f"{func}_slice.dot"
        if sliced:
            out.write_text(sliced)
        else:
            shutil.copy(cfg, out)
        entry['callgraph'] = str(cg.relative_to(report_dir))
        entry['cfg_slice'] = str(out.relative_to(report_dir))
        summary.append(entry)

    print("\x1b[93m[*] Now invoking RAG to enrich findings and generate final report...\x1b[0m")
    (report_dir / 'rag_inputs.json').write_text(json.dumps(summary, indent=2))

    report_path = None
    
    if args.mode == 'gpt':
        try:
            report_path = send_to_gpt(report_dir, summary)
        except Exception as e:
            print(f"\x1b[91m[ERROR] GPT analysis failed: {e}\x1b[0m")
            print("\x1b[93m[*] Falling back to local report generation...\x1b[0m")
            report_path = generate_local_report(report_dir, summary)
    elif args.mode == 'ollama':
        try:
            report_path = send_to_ollama(report_dir, summary, args.ollama_model)
        except Exception as e:
            print(f"\x1b[91m[ERROR] Ollama analysis failed: {e}\x1b[0m")
            print("\x1b[93m[*] Falling back to local report generation...\x1b[0m")
            report_path = generate_local_report(report_dir, summary)
    else:
        report_path = generate_local_report(report_dir, summary)
        print("\x1b[93m[*] No super-intelligence (even AGI achieved in-house) have been passed.. just creating files and leaving!\x1b[0m")

    zip_path = create_report_zip(report_dir)
    print(f"\x1b[96m[+] Report zip available at: {zip_path}\x1b[0m")

    if report_path:
            print(f"\x1b[92m[✔]\x1b[0m \x1b[96mGolem\x1b[0m smashed some bugs! Your report wait at: \x1b[92m{report_path}\x1b[0m")
            
    print("\x1b[92m[✔] Report is ready in 'golem_report'! Golem rests, security prevails.\x1b[0m")


if __name__ == '__main__':
    main()