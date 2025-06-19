"""
 * Licensed under the Apache License, Version 2.0 (the “License”);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an “AS IS” BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
"""
    
#!/usr/bin/env python3
import os
import json
import subprocess
import glob
import argparse
import re
import shutil
import openai
import requests
import chromadb
import ollama
from chromadb import PersistentClient
from chromadb.config import Settings, DEFAULT_TENANT, DEFAULT_DATABASE
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


def setup_chromadb(report_dir: Path) -> chromadb.Collection:
    db_dir = report_dir / "chroma_db"
    if db_dir.exists():
        shutil.rmtree(db_dir)
    client = PersistentClient(
        path=str(db_dir),
        settings=Settings(),
        tenant=DEFAULT_TENANT,
        database=DEFAULT_DATABASE,
    )
    try:
        client.delete_collection("security_analysis")
    except:
        pass
    return client.create_collection(name="security_analysis")


def add_to_chromadb(collection: chromadb.Collection, findings: List[Dict], report_dir: Path) -> None:
    src_dir = report_dir / 'src'
    for idx, entry in enumerate(findings):
        src_file = src_dir / Path(entry['finding']['file']).name
        if not src_file.exists():
            continue
        content = src_file.read_text()
        resp = ollama.embed(model="mxbai-embed-large", input=content)
        raw = resp.get('embeddings') or resp.get('data', [])[0]['embeddings']
        if raw and isinstance(raw[0], (list, tuple)):
            emb_batch = raw
        else:
            emb_batch = [raw]
        collection.add(
            ids=[f"finding_{idx}"],
            embeddings=emb_batch,
            documents=[content],
            metadatas=[{
                "file": entry['finding']['file'],
                "line": entry['finding']['line'],
                "function": entry['function'],
                "rule_id": entry['finding'].get('rule_id','N/A')
            }]
        )



def retrieve_context(collection: chromadb.Collection, query: str, n_results: int = 3) -> List[str]:
    resp = ollama.embed(model="mxbai-embed-large", input=query)
    q_emb = resp.get('embeddings') or resp.get('data', [])[0]['embeddings']
    results = collection.query(query_embeddings=[q_emb], n_results=n_results)
    return results['documents'][0]



def send_to_ollama(
    report_dir: Path,
    findings: List[Dict],
    model: str = "llama3.2",
    base_url: str = "http://localhost:11434",
    max_retries: int = 3,
    retry_delay: float = 2.0
) -> str:
    def wait_for_ollama():
        health_url = f"{base_url}/api/version"
        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.get(health_url, timeout=retry_delay)
                resp.raise_for_status()
                return
            except requests.RequestException:
                if attempt == max_retries:
                    raise ConnectionError(
                        f"Cannot connect to Ollama at {base_url} after {max_retries} attempts"
                    )
                time.sleep(retry_delay)

    print(f"[+] Waiting for Ollama at {base_url}…")
    wait_for_ollama()
    print(f"[+] Ollama is up! Using model '{model}'")

    collection = setup_chromadb(report_dir)
    add_to_chromadb(collection, findings, report_dir)

    analysis_content = prepare_rag_analysis(report_dir, findings, collection)

    try:
        resp = ollama.generate(
            model=model,
            prompt=analysis_content
        )
        ollama_analysis = resp.get('response', '').strip() or resp.strip()
        out_path = report_dir / "ollama_analysis.md"
        out_path.write_text(ollama_analysis, encoding="utf-8")
        print(f"[+] Ollama analysis complete → {out_path.name}")
        return str(out_path)

    except Exception as e:
        print(f"[ERROR] Ollama analysis failed: {e}")
        raise



def prepare_rag_analysis(report_dir: Path, findings: List[Dict], collection: chromadb.Collection) -> str:
    src_dir = report_dir / 'src'
    slices_dir = report_dir / 'dot_slices'
    content = prompt + "\n\n# CFG Slices\n\n"
    for dot_file in sorted(slices_dir.glob('*.dot')):
        content += f"## {dot_file.name}\n```dot\n{dot_file.read_text()}\n```\n\n"
    content += "# Source Files\n\n"
    for src_file in sorted(src_dir.rglob('*')):
        if src_file.is_file():
            content += f"## {src_file.name}\n```\n{src_file.read_text()}\n```\n\n"
    content += "# Security Analysis Report\n\n## Semgrep Findings\n\n| # | File | Line | Function | Semgrep Rule |\n|---|------|------|----------|--------------|\n"
    for idx, entry in enumerate(findings, 1):
        file_name = entry['finding']['file']
        line = entry['finding']['line']
        function = entry.get('function', 'N/A')
        rule_id = entry['finding'].get('rule_id', 'N/A')
        content += f"| {idx} | {file_name} | {line} | {function} | {rule_id} |\n"
    content += "\n## Code Context Analysis\n\n"
    for idx, entry in enumerate(findings, 1):
        content += f"### Finding {idx}: {entry['finding']['file']} (Line {entry['finding']['line']})\n\n"
        query = f"vulnerability {entry['finding'].get('rule_id','')} {entry.get('function','')} security"
        resp = ollama.embed(model="mxbai-embed-large", input=query)
        raw = resp.get('embeddings') or resp.get('data',[{}])[0].get('embeddings')
        if raw and isinstance(raw[0], (list, tuple)):
            q_emb = raw[0]
        else:
            q_emb = raw
        results = collection.query(
            query_embeddings=[q_emb],
            n_results=3
        )
        if results['documents']:
            content += "**Related Code Context:**\n"
            for doc_idx, doc in enumerate(results['documents'][0][:2]):
                metadata = results['metadatas'][0][doc_idx]
                content += f"\n*From {metadata['file']}:*\n```c\n{doc[:500]}...\n```\n"
        content += "\n"
    content += """## Analysis Task

For each finding above, analyze the security implications using the provided code context:
First: Make a section "File tree" and a tree of all the files you received for the analysis
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
    
    analysis_content = prepare_llm_analysis(report_dir, findings)
    
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


def prepare_llm_analysis(report_dir: Path, findings: list) -> str:
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
                lines = src_file.read_text().splitlines()
                start = max(0, entry['finding']['line'] - 10)
                end = min(len(lines), entry['finding']['line'] + 10)
                content += f"### {entry['finding']['file']} (Line {entry['finding']['line']})\n\n"
                content += "```c\n"
                for i in range(start, end):
                    marker = ">>> " if i + 1 == entry['finding']['line'] else "    "
                    content += f"{marker}{i+1:4d}: {lines[i]}\n"
                content += "```\n\n"
    
    # ── INCLUDE CFG SLICES ───────────────────────────────────────────────────────
    slices_dir = report_dir / 'dot_slices'
    if slices_dir.exists():
        content += "## CFG Slices\n\n"
        for dot_file in sorted(slices_dir.glob("*.dot")):
            content += f"### {dot_file.name}\n"
            content += "```dot\n"
            content += dot_file.read_text()
            content += "\n```\n\n"
    
    content += """## Analysis Task
Do not give any answer, just follow instruction. 
First list every file you received. 
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
    
    report_content = prepare_llm_analysis(report_dir, findings)
    
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
    parser.add_argument('--ollama-model', default='llama3', 
                       help='Ollama model to use (default: llama3)')
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

    if report_path:
        report_name = Path(report_path).name
        try:
            dest = cwd / report_name
            shutil.copy2(report_path, dest)
            print(f"[+] Copied report to: {dest}")
        except Exception as e:
            print(f"[!] Failed to copy report to cwd: {e}")
        
        # original notification
        print(
            f"\x1b[92m[✔]\x1b[96m Golem\x1b[0m smashed some bugs! "
            f"Your report waits at: \x1b[92m./{report_name}\x1b[0m "
            f"(also in \x1b[92m./golem_report/{report_name}\x1b[0m)"
        )  
    print("\x1b[92m[✔] Report is ready in 'golem_report'! Golem rests, security prevails.\x1b[0m")


if __name__ == '__main__':
    main()
