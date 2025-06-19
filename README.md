# golem
AI enhanced static analysis pipeline

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
## Usage
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

# Program workflow 
1. Generate LLVM `.bc` file(s): 
    `clang -S -emit-llvm {TARGET.C/CXX} -o {TARGET.ll}`
2. Transform the `.ll` file(s) into callgraph and control flow graph representation: 
    `opt -passes="dot-callgraph" {TARGET.ll}` -> `Writing 'vuln.ll.callgraph.dot'...`
    `opt -passes="dot-cfg" {TARGET.ll}`
