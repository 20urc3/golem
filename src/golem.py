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
import requests
import openai
import requests
import chromadb
import ollama
from chromadb import PersistentClient
from chromadb.config import Settings, DEFAULT_TENANT, DEFAULT_DATABASE
import sys
from pathlib import Path
from typing import Set, List, Dict, Optional
import pydot
import time
import signal
import psutil

# Default arguments (if not present command line)
DEFAULT_SEMGREP_RULES_DIR = Path(os.getcwd()) / 'semgrep-rules'
DEFAULT_SEMGREP_OUTPUT    = 'result_scan.json'
DEFAULT_SLICE_DEPTH       = 3
CALLGRAPH_CMD = 'opt -passes="dot-callgraph"'
CFG_CMD = 'opt -passes="dot-cfg"'
ALLOWED_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp'}
FUNC_DEF_REGEX = re.compile(r'^\s*[\w\*\s]+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{')

# Language prompt
LANG_PROMPTS = {
    'en': "You are a security auditor assistant. Analyze the provided Semgrep findings "
          "and graph artifacts to determine if they are true positives, false positives, "
          "or require manual review. Respond in English.",
    'ru': "Вы — помощник аудитора безопасности. Проанализируйте предоставленные результаты "
          "Semgrep и графовые артефакты, чтобы определить, являются ли они истинными "
          "срабатываниями, ложными или требуют ручной проверки. Отвечайте на русском языке.",
    'de': "Sie sind ein Sicherheitsaudit-Assistent. Analysieren Sie die Semgrep-Befunde "
          "und Graphartefakte. Antworten Sie auf Deutsch.",
    'fr': "Vous êtes un assistant d'audit de sécurité. Analysez les résultats Semgrep "
          "et les artefacts graphiques. Répondez en français.",
}

def get_system_prompt(lang: str) -> str:
    return LANG_PROMPTS.get(lang, LANG_PROMPTS['en'])

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

def run_semgrep(project_dir: Path, report_dir: Path,
                rules_dir: Path, output_filename: str) -> bool:
    print(f"[+] Scanning with Semgrep in '{project_dir}' using rules '{rules_dir}'...")
    output_path = report_dir / output_filename
    proc = subprocess.run(
        [
            'semgrep',
            '--timeout', '300',
            '--timeout-threshold', '0',  
            '--max-target-bytes', '0',
            '--config', str(rules_dir),
            f'--json-output={output_path}',
            str(project_dir)
        ],
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


def slice_cfg(cfg_path: Path, target_line: int, depth: int = DEFAULT_SLICE_DEPTH) -> str | None:
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
    lang: str = "en",
    max_retries: int = 3,
    retry_delay: float = 2.0
) -> str:
    def wait_for_ollama():
        for attempt in range(1, max_retries + 1):
            try:
                requests.get(f"{base_url}/api/version", timeout=retry_delay).raise_for_status()
                return
            except requests.RequestException as e:
                print(f"Attempt {attempt}/{max_retries}: Cannot connect to Ollama at {base_url}...")
                if attempt == max_retries:
                    raise ConnectionError(
                        f"Cannot connect to Ollama at {base_url} after {max_retries} attempts.\n"
                        f"Make sure Ollama is running: 'ollama serve' (on host machine)\n"
                        f"Check URL: {base_url}"
                    )
                time.sleep(retry_delay)

    print(f"[+] Connecting to Ollama at {base_url}...")
    wait_for_ollama()
    print(f"[+] Ollama is up! Using model '{model}', lang='{lang}'")

    collection = setup_chromadb(report_dir)
    add_to_chromadb(collection, findings, report_dir)

    system_prompt = get_system_prompt(lang)
    # TODO build report content
    analysis_content = prepare_rag_analysis(report_dir, findings, collection)
    full_prompt = f"{system_prompt}\n\n{analysis_content}"

    response = requests.post(
        f"{base_url}/api/generate",
        json={ "model": model, "prompt": full_prompt, "stream": False},
        timeout=300
    )
    response.raise_for_status()
    
    result = response.json()
    analysis = result.get('response', '').strip()
    if not analysis:
        raise ValueError("Empty response from Ollama")
        
    # TODO use typical string
    out_path = report_dir / "ollama_analysis.md"
    out_path.write_text(analysis, encoding="utf-8")
    print(f"[+] Ollama analysis saved to {out_path.name}")
    return str(out_path)

def prepare_llm_analysis(report_dir: Path, findings: List[Dict]) -> str:
    content = "# Security Analysis Report\n\n"
    # List all received files
    content += "## Files Received\n\n"
    for subdir in ["src", "callgraphs", "dot_slices"]:
        content += f"### {subdir}\n"
        for f in sorted((report_dir / subdir).glob("*")):
            if f.is_file():
                content += f"- {f.name}\n"
        content += "\n"
    # Semgrep findings table
    content += "## Semgrep Findings\n\n"
    content += "| # | File | Line | Function | Rule |\n|---|------|------|----------|------|\n"
    for i, e in enumerate(findings, 1):
        fn = e.get("function", "N/A")
        content += f"| {i} | {e['finding']['file']} | {e['finding']['line']} | {fn} | {e['finding'].get('rule_id','N/A')} |\n"
    content += "\n"
    # Embed call graphs
    content += "## Call Graphs\n\n"
    for cg in sorted((report_dir / "callgraphs").glob("*.dot")):
        content += f"### {cg.name}\n```dot\n{cg.read_text(errors='ignore')}\n```\n\n"
    # Embed CFG slices
    content += "## CFG Slices\n\n"
    for sl in sorted((report_dir / "dot_slices").glob("*.dot")):
        content += f"### {sl.name}\n```dot\n{sl.read_text(errors='ignore')}\n```\n\n"
    # Embed source files
    content += "## Source Files\n\n"
    for src in sorted((report_dir / "src").glob("*")):
        content += f"### {src.name}\n```c\n{src.read_text(errors='ignore')}\n```\n\n"
    # Analysis instructions
    content += (
        "## Analysis Task\n"
        "First, list every file you received. Then for each finding:\n"
        "1. Executive Summary\n"
        "2. Per-Finding Decision Table\n"
        "3. Conclusion\n"
    )
    return content

def prepare_rag_analysis(report_dir: Path, findings: List[Dict], collection: chromadb.Collection) -> str:
    content = "# RAG-Enriched Security Analysis\n\n"
    # List files
    content += "## Files Received\n\n"
    for subdir in ["src", "callgraphs", "dot_slices"]:
        content += f"### {subdir}\n"
        for f in sorted((report_dir / subdir).glob("*")):
            if f.is_file():
                content += f"- **{subdir}/{f.name}**\n"
        content += "\n"
    # Semgrep findings
    content += "## Semgrep Findings\n\n"
    content += "| # | File | Line | Function | Rule |\n|---|------|------|----------|------|\n"
    for i, e in enumerate(findings, 1):
        fn = e.get("function", "N/A")
        content += f"| {i} | {e['finding']['file']} | {e['finding']['line']} | {fn} | {e['finding'].get('rule_id','N/A')} |\n"
    content += "\n"
    # Attach call graphs
    content += "## Call Graphs\n\n"
    for cg in sorted((report_dir / "callgraphs").glob("*.dot")):
        content += f"### {cg.name}\n```dot\n{cg.read_text(errors='ignore')}\n```\n\n"
    # Attach CFG slices
    content += "## CFG Slices\n\n"
    for sl in sorted((report_dir / "dot_slices").glob("*.dot")):
        content += f"### {sl.name}\n```dot\n{sl.read_text(errors='ignore')}\n```\n\n"
    # Source context
    content += "## Source Files\n\n"
    for src in sorted((report_dir / "src").glob("*")):
        content += f"### {src.name}\n```c\n{src.read_text(errors='ignore')}\n```\n\n"
    # RAG prompt
    content += (
        "## Analysis Task\n"
        "Use the above artifacts to:\n"
        "1. Summarize the overall process and outcomes\n"
        "2. For each finding, assess reachability, sanitization, exploitability, impact, verdict\n"
        "3. Provide risk assessment and remediation steps\n"
        "4. Conclude with next-steps recommendations\n"
    )
    return content



def send_to_gpt(report_dir: Path, findings: List[Dict],
                lang: str = "en") -> str:
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    print("[+] Sending analysis to ChatGPT, lang='{lang}'...")
    client = openai.OpenAI(api_key=api_key)
    # TODO use build_report_content
    analysis_content = prepare_llm_analysis(report_dir, findings)
    system_prompt = get_system_prompt(lang)

    response = client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user","content": analysis_content}
        ],
        max_tokens=4000,
        temperature=0.1
    )
        
    analysis = response.choices[0].message.content
    out_path = report_dir / 'gpt_analysis.md'
    out_path.write_text(analysis, encoding="utf-8")
    print("[+] GPT analysis complete and saved to {out_path}")
    return str(out_path)


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
    
    local_report_path = report_dir / 'local_analysis.md'
    local_report_path.write_text(report_content)
    
    print(f"[+] Local report template saved to: {local_report_path}")
    return str(local_report_path)

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Golem — automated C/C++ vulnerability discovery",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # General
    parser.add_argument('project_dir', type=Path, help='Path to C/C++ project')

    # Semgrep
    semgrep_g = parser.add_argument_group('Semgrep options')
    semgrep_g.add_argument(
        '--semgrep-rules', type=Path, default=DEFAULT_SEMGREP_RULES_DIR,
        metavar='DIR',
        help='Path to Semgrep rules directory or config file')
    semgrep_g.add_argument(
        '--semgrep-output', default=DEFAULT_SEMGREP_OUTPUT,
        metavar='FILENAME',
        help='Semgrep JSON output filename (inside report dir)')
    
    # TODO LLVM / .ll generation

    # LLM backend mode
    llm_g = parser.add_argument_group('LLM backend options')
    llm_g.add_argument(
        '--mode', '-m', 
        choices=['local', 'gpt', 'ollama', 'llamacpp'], 
        default='local', 
        help='Analysis mode: local (generate template), ' \
        'gpt (send to GPT-4), ollama or llama-cpp (send to ll server)')
    llm_g.add_argument(
        '--lang',
        choices=list(LANG_PROMPTS.keys()),
        default='en',
        help='Language for LLM system prompt and output report')

    # Ollama
    ollama_g = parser.add_argument_group('Ollama options (--mode ollama)')
    ollama_g.add_argument(
        '--ollama-url', dest='ollama_url', default='http://localhost:11434', metavar='URL',
        help='Ollama server url')
    ollama_g.add_argument(
        '--ollama-model', default='llama3', metavar='MODEL', 
        help='Ollama model name')

    # TODO llama-cpp

    # Output
    out_g = parser.add_argument_group('Output options')
    out_g.add_argument(
        '--report-dir', type=Path, default=None, metavar='DIR',
        help='Directory for all output artefacts (default: ./golem_report)')
    
    return parser

def main():
    if len(sys.argv) == 1:
        print("\x1b[93mNo arguments provided. Run with --help to see usage\x1b[0m")
        return
    
    parser = build_parser()
    args = parser.parse_args()

    project: Path = args.project_dir.resolve()
    cwd = Path.cwd()

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

    # Directories
    report_dir = (args.report_dir or (cwd / 'golem_report')).resolve()
    callgraph_dir = report_dir / 'callgraphs'
    cfg_dir = report_dir / 'cfg'
    slices_dir = report_dir / 'dot_slices'
    # TODO ll_work_dir

    # make folders
    for d in [report_dir, callgraph_dir, cfg_dir, slices_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # TODO Step 1 - generate .ll files

    # Step 2 - run Semgrep
    if not run_semgrep(project, report_dir, args.semgrep_rules, args.semgrep_output):
        print("\x1b[91m[ERROR] Semgrep scan failed. Aborting.\x1b[0m")
        return
    findings = load_semgrep_results(report_dir / args.semgrep_output)
    print(f"\x1b[93m[+] Loaded {len(findings)} Semgrep findings.\x1b[0m")

    copy_source_files(findings, project, report_dir)

    for old in cfg_dir.glob('*.dot'):
        old.unlink()

    # TODO Step 3 - graphs and slices    

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
        sliced = slice_cfg(cfg, entry['finding']['line']) # TODO use depth
        out = slices_dir / f"{func}_slice.dot"
        if sliced:
            out.write_text(sliced)
        else:
            shutil.copy(cfg, out)
        entry['callgraph'] = str(cg.relative_to(report_dir))
        entry['cfg_slice'] = str(out.relative_to(report_dir))
        summary.append(entry)

    # Step 4. LLM Analyze
    print("\x1b[93m[*] Running LLM analysis (mode={args.mode}, lang={args.lang})...\x1b[0m")
    (report_dir / 'rag_inputs.json').write_text(json.dumps(summary, indent=2))
    report_path: Optional[str] = None
    
    try:
        if args.mode == 'gpt':
            report_path = send_to_gpt(report_dir, summary, lang=args.lang)
        elif args.mode == 'ollama':
            report_path = send_to_ollama(
                report_dir, summary, 
                model=args.ollama_model,
                base_url=args.ollama_url,
                lang=args.lang
            )
        # TODO add llamacpp    
        else: # local
            report_path = generate_local_report(report_dir, summary)
            print("\x1b[93m[*] No super-intelligence (even AGI achieved in-house) have been passed.. just creating files and leaving!\x1b[0m")    

    except Exception as e:
        print(f"\x1b[91m[ERROR] LLM backend failed: {e}\x1b[0m")
        print("\x1b[93m[*] Falling back to local report generation...\x1b[0m")
        report_path = generate_local_report(report_dir, summary)

    # Step 5. Copy result TODO use pandoc
    if report_path:
        report_name = Path(report_path).name
        dest = cwd / report_name
        try:
            shutil.copy2(report_path, dest)
            print(f"[+] Copied report to: {dest}")
        except Exception as e:
            print(f"[!] Failed to copy report to cwd: {e}")
        
        # original notification
        print(
            f"\x1b[92m[✔]\x1b[96m Golem\x1b[0m done! "
            f"Your report waits at: \x1b[92m./{report_name}\x1b[0m "
            f"(also in \x1b[92m{report_dir}/{report_name}\x1b[0m)"
        )  
    print("\x1b[92m[✔] Report is ready in 'golem_report'! Golem rests, security prevails.\x1b[0m")


if __name__ == '__main__':
    main()
