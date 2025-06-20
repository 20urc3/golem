# golem
Golem automates C/C++ vulnerability discovery by combining Semgrep rule scans, LLVM call-graph & CFG slicing, and AI-driven context analysis. It flags potential security issues, generates rich graph artifacts, and leverages large-language models (GPT-4 or Ollama) to produce a detailed, prioritized audit report, so you can find and fix critical bugs faster.

## Usage
Prepare your target project to analyze then run 

`golem.py [-h] [--mode {local,gpt,ollama}] [--ollama-model OLLAMA_MODEL] project_dir`
### Prepare your project
Compile your target project with these flags:
cmake:
```
cmake \
  -DCMAKE_C_COMPILER=clang \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_C_FLAGS="-S -emit-llvm" \
  -DCMAKE_CXX_FLAGS="-S -emit-llvm" \
  /path/to/your/source
make
```
make:
```
make CC=clang \
     CXX=clang++ \
     CFLAGS="-S -emit-llvm" \
     CXXFLAGS="-S -emit-llvm"
```
This will create .ll file(s) in your project folder

## Requirements
- Python3
- pip3
- graphviz
- LLVM >= 18
- semgrep
- pydot >= 4.0.1

For local LLM version:
- ollama >= 0.5.1
- ChromaDB
You can install them manually or run: `pip install -r requirements.txt`
# General worflow
1. Generate LLVM `.bc` file(s): 
    `clang -S -emit-llvm {TARGET.C/CXX} -o {TARGET.ll}`
2. Transform the `.ll` file(s) into callgraph and control flow graph representation: 
    `opt -passes="dot-callgraph" {TARGET.ll}` -> `Writing 'vuln.ll.callgraph.dot'...`
    `opt -passes="dot-cfg" {TARGET.ll}`
3. Run semgrep against the project of your choice.
4. Analyze results and slice callgraph/control flow graph to enhance RAG
5. Send prompt + files to RAG
6. Return a report

# Trophies
If you find a bug with this tool, please report it ! We'll gladly add it to the list :)

# Contributors
- Author(s): 2ourc3 - Salim LARGO
