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
import io
import json
import subprocess
import argparse
import re
import shutil
import requests
import openai
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
import concurrent.futures
import threading

# Default arguments (if not present command line)
DEFAULT_SEMGREP_RULES_DIR = Path(os.getcwd()) / 'semgrep-rules'
DEFAULT_SEMGREP_OUTPUT    = 'result_scan.json'
DEFAULT_SLICE_DEPTH       = 3
DEFAULT_LLM_TIMEOUT = 600  # seconds
MAX_DOT_NODES = 50  # for LLM
MAX_DOT_EDGES = 100  # for LLM
ALLOWED_EXTENSIONS = {'.c', '.cpp', '.h', '.hpp', '.cxx', '.cc'}
FUNC_DEF_REGEX = re.compile(
    r'^\s*[\w\*\s]+\s+(?P<name>\w+)\s*\([^)]*\)\s*\{'
)

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
                rules_dir: Path, output_filename: str,
                exclude_patterns: List[str] = None) -> bool:
    print(f"[+] Scanning with Semgrep in '{project_dir}' using rules '{rules_dir}'...")
    output_path = report_dir / output_filename
    cmd = [
        'semgrep',
        '--timeout', '300',
        '--timeout-threshold', '0',
        '--max-target-bytes', '0',
        '--config', str(rules_dir),
        '--json',
        '-o', str(output_path),
    ]
    if exclude_patterns:
        for pat in exclude_patterns:
            cmd += ['--exclude-rule', pat]
        print(f"  [i] Excluding patterns: {exclude_patterns}")
    
    cmd.append(str(project_dir))
    print(f"  [i] Running: {' '.join(cmd[:5])}...")

    proc = subprocess.run(
        cmd,
        cwd=project_dir,
        capture_output=True,
        text=True
    )

    if proc.returncode != 0:
        print(f"  [!] Semgrep warning/error: {proc.stderr[:200]}")
        if not output_path.exists():
            print(f"  [ERROR] No output file generated")
            return False

    print("[+] Semgrep done!")
    return True


def load_semgrep_results(path: Path) -> list:
    data = json.loads(path.read_text())
    findings = []
    for res in data.get('results', []):
        p = res.get('path')
        src = p.get('repr') if isinstance(p, dict) else p
        if not src or Path(src).suffix.lower() not in ALLOWED_EXTENSIONS:
            continue
        findings.append({
            'finding': {
                'file': src,
                'line': res['start']['line'],
                'rule_id': res.get('check_id')
            },
            'function': res.get('extra', {}).get('metadata', {}).get('function')
        })
    return findings


# Automatic generate .ll files using clang compiler
def _clang_compile_single(src: Path, out_ll: Path,
                           extra_flags: List[str] = None) -> bool:
    suffix = src.suffix.lower()
    compiler = 'clang++' if suffix in {'.cpp', '.cxx', '.cc', '.hpp'} else 'clang'
    flags = [
        '-S', '-emit-llvm',
        '-g0',            # without debug info
        '-O0',            # without optimization
        '-w',             # disable warnings
        '-I', str(src.parent),
    ]
    if extra_flags:
        flags.extend(extra_flags)

    cmd = [compiler] + flags + [str(src), '-o', str(out_ll)]
    result = subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=120
    )
    if result.returncode != 0:
        # print only first error line
        first_err = result.stderr.decode(errors='replace').splitlines()
        hint = first_err[0] if first_err else '(no output)'
        print(f"  [!] {src.name}: {hint}")
        return False
    return True


# Recursively find all .c .cpp files in project dit and compile to .ll
def generate_ll_for_project(project_dir: Path, ll_output_dir: Path,
                              extra_include_dirs: List[str] = None,
                              jobs: int = 4) -> List[Path]:
    
    ll_output_dir.mkdir(parents=True, exist_ok=True)

    # get all include flags
    extra_flags: List[str] = []
    if extra_include_dirs:
        for inc in extra_include_dirs:
            extra_flags += ['-I', inc]

    # find include folders
    for candidate in ['include', 'inc', 'src', 'lib', 'common', 'headers']:
        inc_path = project_dir / candidate
        if inc_path.is_dir():
            extra_flags += ['-I', str(inc_path)]

    sources = []
    for ext in ['*.c', '*.cpp', '*.cxx', '*.cc']:
        sources.extend(project_dir.rglob(ext))
    print(f"[+] Found {len(sources)} source files. Compiling to LLVM IR "
          f"(jobs={jobs})...")

    generated: List[Path] = []
    lock = threading.Lock()

    def _compile(src: Path):
        # make unique name
        rel = src.relative_to(project_dir)
        stem = str(rel).replace('/', '_').replace('\\', '_').replace(' ', '_')
        out_ll = ll_output_dir / (stem + '.ll')
        if out_ll.exists():
            with lock:
                generated.append(out_ll)
            return
        ok = _clang_compile_single(src, out_ll, extra_flags)
        if ok:
            with lock:
                generated.append(out_ll)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as ex:
        list(ex.map(_compile, sources))

    print(f"[+] Successfully compiled {len(generated)}/{len(sources)} files to .ll")
    return generated


def infer_function_name(source_file: Path, line_no: int) -> str | None:
    name = None
    try:
        for idx, line in enumerate(source_file.read_text().splitlines(), start=1):
            if idx > line_no: break
            m = FUNC_DEF_REGEX.match(line)
            if m: name = m.group('name')
    except Exception:
        pass
    return name


def find_ll_file(source_path: str, root: Path,
                project_dir: Optional[Path] = None) -> Optional[Path]:

    src = Path(source_path)
    base_stem = src.stem
    all_ll = list(root.rglob('*.ll'))

    # 1. Flatten
    if project_dir:
        try:
            rel = src.relative_to(project_dir)
        except ValueError:
            rel = src
        flat_stem = str(rel).replace('/', '_').replace('\\', '_').replace(' ', '_')
        for ll in all_ll:
            if ll.stem == flat_stem:
                return ll

    # 2. Stem
    for ll in all_ll:
        if ll.stem == base_stem:
            return ll

    # 3. Suffix
    for ll in all_ll:
        if ll.stem.endswith('_' + base_stem):
            return ll

    return None


def generate_graphs(ll_file: Path, callgraph_dir: Path, cfg_dir: Path) -> Path:
    print(f"  [+] Generating LLVM callgraph and CFG for {ll_file.name}...")
    stem = ll_file.stem
    cg_dot = callgraph_dir / f"{stem}.ll.callgraph.dot"
    r1 = subprocess.run(
        f'opt -passes="dot-callgraph" "{ll_file}" -o "{cg_dot}"',
        cwd=str(callgraph_dir), shell=True,
        capture_output=True, text=True
    )
    if not cg_dot.exists():
        raise subprocess.CalledProcessError(
            r1.returncode, 'opt dot-callgraph', r1.stderr
        )

    # CFG — cwd=cfg_dir
    r2 = subprocess.run(
        f'opt -passes="dot-cfg" "{ll_file}" -o /dev/null',
        cwd=str(cfg_dir), shell=True,
        capture_output=True, text=True,
    )
    # opt : ".foo.dot" to "foo.dot"
    for hidden in list(cfg_dir.glob(".*.dot")):
        visible = hidden.parent / hidden.name.lstrip('.')
        hidden.rename(visible)

    cfg_count = len(list(cfg_dir.glob("*.dot")))
    if cfg_count == 0:
        print(f"  [!] dot-cfg: no .dot for {ll_file.name}")
        if r2.stderr:
            print(f"      {r2.stderr[:200]}")    

    print(f"[+] CFG ({cfg_count}) and callgraph generation done!")
    return cg_dot


def slice_cfg(cfg_path: Path, target_line: int, 
              depth: int = DEFAULT_SLICE_DEPTH) -> Optional[str]:
    graphs = pydot.graph_from_dot_file(str(cfg_path)) or []
    if not graphs:
        return None
    graph = graphs[0]
    nodes = [n for n in graph.get_nodes()
             if f":{target_line}" in n.get_attributes().get('label', '')]
    if not nodes:
        return None
    slice_nodes: Set = set(nodes)
    frontier: Set = set(nodes)
    for _ in range(depth):
        next_front: Set = set()
        for e in graph.get_edges():
            src, dst = e.get_source(), e.get_destination()
            if any(n.get_name() == dst for n in frontier):
                next_front.update(n for n in graph.get_nodes() if n.get_name()==src)
            if any(n.get_name() == src for n in frontier):
                next_front.update(n for n in graph.get_nodes() if n.get_name()==dst)
        slice_nodes |= next_front
        frontier = next_front
    sub = pydot.Dot(graph_type='digraph') 
    names = {n.get_name() for n in slice_nodes}
    for n in slice_nodes: 
        sub.add_node(n)
    for e in graph.get_edges():
        if e.get_source() in names and e.get_destination() in names: 
            sub.add_edge(e)
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
            except Exception as e:
                print(f"  [!] Error copying {src_file}: {e}")
        else:
            print(f"  [!] Source file not found: {src_file}")
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
    include_sources: bool = False,
    max_retries: int = 3,
    retry_delay: float = 2.0,
    timeout: int = DEFAULT_LLM_TIMEOUT,
    simplify_graphs: bool = True,
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

    # TODO check that it usage
    #collection = setup_chromadb(report_dir)
    #add_to_chromadb(collection, findings, report_dir)

    full_prompt = (get_system_prompt(lang) + "\n\n"
            + _build_report_content(report_dir, findings,
                                    include_sources=include_sources,
                                    simplify_graphs=simplify_graphs))

    response = requests.post(
        f"{base_url}/api/generate",
        json={ "model": model, "prompt": full_prompt, "stream": False},
        timeout=timeout
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

def send_to_llamacpp(
    report_dir: Path,
    findings: List[Dict],
    base_url: str,
    api_key: str = "",
    model: str = "default",
    lang: str = "en",
    max_tokens: int = 4096,
    temperature: float = 0.1,
    include_sources: bool = False,
    timeout: int = DEFAULT_LLM_TIMEOUT,
    simplify_graphs: bool = True,
) -> str:
    health_url = f"{base_url.rstrip('/')}/health"
    try:
        r = requests.get(health_url, timeout=10)
        print(f"[+] llama-cpp server is up at {base_url} (status: {r.status_code})")
    except requests.RequestException:
        # if /health not present
        try:
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            r = requests.get(f"{base_url.rstrip('/')}/v1/models",
                             headers=headers, timeout=10)
            print(f"[+] llama-cpp server is up at {base_url}")
        except requests.RequestException as e:
            raise ConnectionError(
                f"Cannot reach llama-cpp server at {base_url}.\n"
                f"Start it with: python -m llama_cpp.server --model <model.gguf> "
                f"--host 0.0.0.0 --port 8080\n"
                f"Error: {e}"
            )

    analysis_content = _build_report_content(
        report_dir, findings, 
        include_sources=include_sources,
        simplify_graphs=simplify_graphs
        )
    system_prompt = get_system_prompt(lang)

    est_chars = len(system_prompt) + len(analysis_content)
    est_tokens = est_chars // 4
    print(f"[+] Prompt: ~{est_chars:,} chars (~{est_tokens:,} tokens estimated)")
    if est_tokens > max_tokens * 0.8:
        print(
            f"  [!] Prompt (~{est_tokens} tok) is >80% max_tokens ({max_tokens}).\n"
            f"      Fix: increase --n_ctx and --llamacpp-max-tokens on server\n"
            f"      or decrease Semgrep rules count (--semgrep-exclude)."
        )

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": analysis_content},
        ],
        "max_tokens": max_tokens,
        "temperature": temperature,
        "stream": False,
    }

    print(f"[+] Sending analysis to llama-cpp ({base_url}), model='{model}', lang='{lang}', max-tokens='{max_tokens}'...")
    response = requests.post(
        f"{base_url.rstrip('/')}/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()

    data = response.json()
    finish = data.get("choices", [{}])[0].get("finish_reason", "")
    if finish == "length":
        print(
            "  [!] finish_reason=length: response was cropped!\n"
            "      Increase --n_ctx and --llamacpp-max-tokens."
        )

    analysis = data["choices"][0]["message"]["content"].strip()
    if not analysis:
        raise ValueError("Empty response from llama-cpp server")

    out_path = report_dir / "llamacpp_analysis.md"
    out_path.write_text(analysis, encoding="utf-8")
    print(f"[+] llama-cpp analysis saved → {out_path.name}")
    return str(out_path)

def _truncate(text: str, max_chars: int, label: str = "") -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    marker = f"\n\n... [{label} TRUNCATED {len(text):,} → {max_chars:,} chars] ...\n\n"
    return text[:half] + marker + text[-half:]

def _build_report_content(
    report_dir: Path, 
    findings: List[Dict],
    include_sources: bool = False,
    max_dot_chars: int = 8_000,
    max_src_chars: int = 6_000,
    simplify_graphs: bool = True,
    ) -> str:
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

    if findings:
        content += "| # | File | Line | Function | Rule |\n"
        content += "|---|------|------|----------|------|\n"
        for i, e in enumerate(findings, 1):
            fn = e.get("function", "N/A")
            content += (
                f"| {i} | {e['finding']['file']} | {e['finding']['line']} "
                f"| {fn} | {e['finding'].get('rule_id', 'N/A')} |\n"
            )
        content += "\n"
    else:
        content += "_No findings to analyze._\n\n"

    # Embed call graphs
    cg_dir = report_dir / "callgraphs"
    if cg_dir.exists():
        dots = sorted(cg_dir.glob("*.dot"))
        if dots:
            content += "## Call Graphs\n\n"
            per = max(max_dot_chars // len(dots), 800)
            for cg in dots:
                raw = cg.read_text(errors='ignore')
                content += f"### {cg.name}\n```dot\n"
                content += _truncate(raw, per, cg.name)
                content += "\n```\n\n"

    # Embed CFG slices
    sl_dir = report_dir / "dot_slices"
    if sl_dir.exists():
        dots = sorted(sl_dir.glob("*.dot"))
        if dots:
            content += "## CFG Slices\n\n"
            per = max(max_dot_chars // len(dots), 800)
            for sl in dots:
                raw = sl.read_text(errors='ignore')
                content += f"### {sl.name}\n```dot\n"
                content += _truncate(raw, per, sl.name)
                content += "\n```\n\n"

    # Embed source files
    if include_sources:
        src_d = report_dir / "src"
        if src_d.exists():
            srcs = sorted(f for f in src_d.glob("*") if f.is_file())
            if srcs:
                content += "## Source Files\n\n"
                per = max(max_src_chars // len(srcs), 400)
                for src in srcs:
                    raw = src.read_text(errors='ignore')
                    content += f"### {src.name}\n```c\n"
                    content += _truncate(raw, per, src.name)
                    content += "\n```\n\n"

    # Analysis instructions
    content += (
        "## Analysis Task\n"
        "For each finding:\n"
        "1. **Executive Summary** — vulnerability class and affected function\n"
        "2. **Decision Table** — reachable? sanitized? "
        "Verdict: True Positive / False Positive / Manual Review\n"
        "3. **Remediation** — concrete fix recommendation\n"
        "4. **Conclusion** — overall risk level\n"
    )
    return content


def send_to_gpt(
        report_dir: Path, 
        findings: List[Dict],
        lang: str = "en",
        include_sources: bool = False,
        timeout: int = DEFAULT_LLM_TIMEOUT,
        simplify_graphs: bool = True,
    ) -> str:
    api_key = os.getenv('OPENAI_API_KEY')
    if not api_key:
        raise ValueError("OPENAI_API_KEY environment variable not set")
    
    print("[+] Sending analysis to ChatGPT, lang='{lang}'...")
    client = openai.OpenAI(api_key=api_key)
    analysis_content = _build_report_content(
        report_dir, findings, 
        include_sources=include_sources,
        simplify_graphs=simplify_graphs
        )
    system_prompt = get_system_prompt(lang)

    response = client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user","content": analysis_content}
        ],
        max_tokens=4000,
        temperature=0.1,
        timeout=timeout,
    )
        
    analysis = response.choices[0].message.content
    out_path = report_dir / 'gpt_analysis.md'
    out_path.write_text(analysis, encoding="utf-8")
    print("[+] GPT analysis complete and saved to {out_path}")
    return str(out_path)


def generate_local_report(report_dir: Path, findings: list) -> str:
    print("[+] Generating local markdown report...")
    content = _build_report_content(report_dir, findings)
    content += (
        "\n---\n\n## Manual Analysis Template\n\n"
        "### Executive Summary\n[Your analysis here]\n\n"
        "### Detailed Analysis\n[Per-finding analysis here]\n\n"
        "### Conclusion\n[Overall risk assessment and recommendations]\n"
    )
    out_path = report_dir / 'local_analysis.md'
    out_path.write_text(content, encoding="utf-8")
    print(f"[+] Local report template saved to: {out_path.name}")
    return str(out_path)

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
    semgrep_g.add_argument('--semgrep-exclude', action='append',
                    dest='semgrep_exclude', default=[], metavar='PATTERN',
                    help=(
                        'Exclude semgrep rules by pattern (list).\n'
                        'Example:\n'
                        '  --semgrep-exclude "*.tpl.yaml"  — taint/semantic rules\n'
                        '  --semgrep-exclude "taint*"\n'
                        '  --semgrep-exclude "semantic*"\n'
                        'Usage if Semgrep evaulate too long.'
                    ))
    
    # LLVM / .ll generation
    llvm_g = parser.add_argument_group('LLVM .ll generation options')
    llvm_g.add_argument(
        '--auto-ll', action='store_true',
        help='Auto-compile project sources to .ll with clang (no pre-built .ll needed)')
    llvm_g.add_argument(
        '--ll-dir', type=Path, default=None,
        metavar='DIR',
        help='Directory with pre-built .ll files (if not using --auto-ll). '
             'Defaults to <project_dir>')
    llvm_g.add_argument(
        '--include', action='append', dest='extra_includes', default=[],
        metavar='DIR',
        help='Extra -I include directory for clang (can be repeated)')
    llvm_g.add_argument(
        '--jobs', type=int, default=4,
        metavar='N',
        help='Parallel clang jobs for --auto-ll')
    llvm_g.add_argument(
        '--slice-depth', type=int, default=DEFAULT_SLICE_DEPTH,
        metavar='N',
        help='CFG backward/forward slice depth')

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
    llm_g.add_argument('--include-sources', action='store_true', default=False,
                    help=(
                        'Include project sources to LLM prompt.\n'
                        'WARNING: it increase prompt size and token count.\n'
                        'Safely for GPT-4 or model with 32k+ context.\n'
                        'For local llama-cpp or Ollama with 4b-model dont use this flag.'
                    ))
    llm_g.add_argument(
        '--llm-timeout', type=int, default=DEFAULT_LLM_TIMEOUT,
        metavar='SECONDS',
        help='Timeout for LLM API calls (seconds)'
    )
    llm_g.add_argument(
        '--simplify-graphs', action='store_true', default=True,
        help='Simplify DOT graphs to reduce token usage (recommended)'
    )
    llm_g.add_argument(
        '--no-simplify-graphs', dest='simplify_graphs', action='store_false',
        help='Disable graph simplification (may increase token usage)'
    )

    # Ollama
    ollama_g = parser.add_argument_group('Ollama options (--mode ollama)')
    ollama_g.add_argument(
        '--ollama-url', dest='ollama_url', default='http://localhost:11434', metavar='URL',
        help='Ollama server url')
    ollama_g.add_argument(
        '--ollama-model', default='llama3', metavar='MODEL', 
        help='Ollama model name')

    # llama-cpp
    llamacpp_g = parser.add_argument_group('llama-cpp options (--mode llamacpp)')
    llamacpp_g.add_argument(
        '--llamacpp-url', default='http://localhost:8080', metavar='URL',
        help='llama-cpp-python server URL (OpenAI-compatible)')
    llamacpp_g.add_argument(
        '--llamacpp-key', default='', metavar='KEY',
        help='API key for llama-cpp server (if --api-key was set on server)')
    llamacpp_g.add_argument(
        '--llamacpp-model', default='default', metavar='MODEL',
        help='Model name to send in the request (for multi-model servers)')
    llamacpp_g.add_argument(
        '--llamacpp-max-tokens', type=int, default=4096, metavar='N',
        help='max_tokens for llama-cpp generation')
    llamacpp_g.add_argument(
        '--llamacpp-temperature', type=float, default=0.1, metavar='F',
        help='Temperature for llama-cpp generation')

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
    ll_work_dir   = report_dir / 'll_files'

    # make folders
    for d in [report_dir, callgraph_dir, cfg_dir, slices_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Step 1 - generate .ll files
    if args.auto_ll:
        ll_work_dir.mkdir(exist_ok=True)
        generated_ll = generate_ll_for_project(
            project_dir=project,
            ll_output_dir=ll_work_dir,
            extra_include_dirs=args.extra_includes,
            jobs=args.jobs,
        )
        ll_search_root = ll_work_dir
    else:
        ll_search_root = args.ll_dir.resolve() if args.ll_dir else project

    # Step 2 - run Semgrep
    if not run_semgrep(project, report_dir, args.semgrep_rules,
                       args.semgrep_output, args.semgrep_exclude):
        print("\x1b[91m[ERROR] Semgrep scan failed. Aborting.\x1b[0m")
        return
    findings = load_semgrep_results(report_dir / args.semgrep_output)
    print(f"\x1b[93m[+] Loaded {len(findings)} Semgrep findings.\x1b[0m")

    copy_source_files(findings, project, report_dir)

    for old in cfg_dir.glob('*.dot'):
        old.unlink()

    # Step 3 - graphs and slices
    summary: List[Dict] = []
    processed_ll: Set[Path] = set()

    for entry in findings:
        src_file = project / entry['finding']['file']
        func = entry['function'] or infer_function_name(src_file, entry['finding']['line'])
        if not func:
            print(f"  [!] Unknown function in {entry['finding']['file']}:"
                  f"{entry['finding']['line']}")
            summary.append(entry)
            continue
        entry['function'] = func

        ll = find_ll_file(entry['finding']['file'], ll_search_root,
                          project_dir=project)
        if not ll:
            print(f"  [!] No .ll found for {entry['finding']['file']} "
                  f"(use --auto-ll to generate automatically)")
            summary.append(entry)
            continue

        if ll not in processed_ll:
            try:
                cg = generate_graphs(ll, callgraph_dir, cfg_dir)
                processed_ll.add(ll)
            except subprocess.CalledProcessError as e:
                print(f"  [!] Graph generation failed for {ll.name}: {e}")
                summary.append(entry)
                continue
            processed_ll.add(ll)
        else:
            # find already generated callgraph
            cg_candidates = list(callgraph_dir.glob(f"{ll.stem}*.dot"))
            cg = cg_candidates[0] if cg_candidates else callgraph_dir / f"{ll.stem}.ll.callgraph.dot"

        cfg_candidates = list(cfg_dir.glob(f"*{func}.dot"))
        if not cfg_candidates:
            print(f"  [!] No CFG .dot for function '{func}'")
            entry['callgraph'] = str(cg.relative_to(report_dir))
            summary.append(entry)
            continue

        cfg = cfg_candidates[0]
        sliced = slice_cfg(cfg, entry['finding']['line'], depth=args.slice_depth)
        out_slice = slices_dir / f"{func}_slice.dot"
        if sliced:
            out_slice.write_text(sliced)
        else:
            shutil.copy(cfg, out_slice)

        entry['callgraph'] = str(cg.relative_to(report_dir))
        entry['cfg_slice'] = str(out_slice.relative_to(report_dir))
        summary.append(entry)

    (report_dir / 'rag_inputs.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(f"[+] rag_inputs.json: {len(summary)} entries")

    # Step 4. LLM Analyze
    print(f"\x1b[93m[*] Running LLM analysis (mode={args.mode}, lang={args.lang})...\x1b[0m")
    report_path: Optional[str] = None
    
    try:
        if args.mode == 'gpt':
            report_path = send_to_gpt(
                report_dir, 
                summary, 
                lang=args.lang,
                include_sources=args.include_sources,
                timeout=args.llm_timeout,
                simplify_graphs=args.simplify_graphs
                )
        elif args.mode == 'ollama':
            report_path = send_to_ollama(
                report_dir, summary, 
                model=args.ollama_model,
                base_url=args.ollama_url,
                lang=args.lang,
                include_sources=args.include_sources,
                timeout=args.llm_timeout,
                simplify_graphs=args.simplify_graphs
                )
        elif args.mode == 'llamacpp':
            report_path = send_to_llamacpp(
                report_dir, summary,
                base_url=args.llamacpp_url,
                api_key=args.llamacpp_key,
                model=args.llamacpp_model,
                lang=args.lang,
                max_tokens=args.llamacpp_max_tokens,
                temperature=args.llamacpp_temperature,
                include_sources=args.include_sources,
                timeout=args.llm_timeout,
                simplify_graphs=args.simplify_graphs
                )
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
