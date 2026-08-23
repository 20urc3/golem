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

--- 
# Golem — Engineering AI for Static Security Analysis

## Introduction

Have you ever tried to build furniture and somehow you got more (or less) parts than what you'd expect. You end up with a tiny stick of wood and 3 screws and your furniture seems to be done ? Reading the documentation is for the weak so you pull up your phone and ask ChatGPT: How many of those things I should have ?

![image](docs/img/image1.png)

You check by yourself and what on Earth is ChatGPT yapping about ? There is now way there are that many parts left in the bag and 5 are already in the wardrobe. But wait, since a while now GPT (and others) accept document input. So, smart as you are, you download the instruction and immediately send it !

![image](docs/img/image2.png)

Fantastic! This time it found the right number left in the bag, which are obviously some replacement pieces IKEA decided to add (which make perfect sense) job done !

### What about Cybersec ?

As a security researcher I'm always trying to find bug, and more importantly to build tool that find them for me. That's why I naturally tried finding things with LLM. After all, this super-intelligence is capable of resolving complex tasks I couldn't, why not auditing a code base ?

Let's give it a try and ask ChatGPT to find a vulnerability in libsndfile:

![image](docs/img/image3.png)

Houra! No need for me to ever audit code ever again. Let's go investigate this bug immediately!

![image](docs/img/image4.png)

Total despair, the vulnerability doesn't exist. It seems that the same issue persists, completely made up function/arguments in an existing function..

But wait, LLM accepts large context, what if I pass it the entire file ? Certainly it won't make up things anymore!

![image](docs/img/image5.png)
![image](docs/img/image6.png)

Ok this time it's very serious and it seems like a valid bug!

![image](docs/img/image7.png)

Woaw, that's frustrating. The LLM couldn't find any bugs so it decided to make one up based on real code, it actually made something sensible that looked really closely to the code.

After this frustrating experience I decided to never use an LLM for auditing ever again.. or not?

## Putting things in order

Let's put things back in context. LLMs are nothing else (so far) than text completion on steroids. Certainly it's able to do very interesting things but it's very far from deterministic when it comes to finding bugs. What if instead we used it for what it's good like putting things together, writing, etc ?

A few years ago I came across this fantastic work from 0xdea, a [list of C/++ vulnerabilities detection rules for SemGrep](https://github.com/0xdea/semgrep-rules) !

If you have never used [SemGrep](https://github.com/semgrep/semgrep) it's basically like regular expression on steroids, it allows you to write complex rules and cover a multitude of languages. The strength of SemGrep is that it is parsing the language into an AST which allows the user to write more complex rules than a simple regex.

![image](docs/img/image8.png)

This works pretty well and with the nice set of SemGrep rules we got for C/bugs.

![image](docs/img/image9.png)

One of the issues is that SemGrep operates on a too high level of abstractiwith the price of an important number of findings that are false positives.

## Programming crash course

All of you have seen the most basic example of programming (if not, go for

![image](docs/img/image-10.png)

But do you how it looks on it's AST form ?

![image](docs/img/image-11.png)

Who would have thought that a short program like this could be that big! Itn this case the interpreter, cannot understand high level concepts. Thosethings are for humans, the machine needs precise and complete instructions in order to process inputs correctly. This is on this level (AST) that SemGrep operates!

Those of you who have been a bit more curious have probably tried a compile


![image](docs/img/image-12.png)

Except for some C shenanigans, this example is super straightforward too! Ber ? Have you tried to understand WHAT is actually produces when you hit the"compile" button.


![image](docs/img/image-13.png)

This is what your code looks like when it's about to be assembled, transfororgive me for the AT&T syntax)
                                                                                                                                                                               ![image](docs/img/image-14.png)Ok I get it you are a haxxor and you obviously know assembly, super easy yon thinking and objcopy is your best friend. But did you know that a lot ofmodern languages rely on a stage in between the C/C++ and the Assembly ? Itentation, think of it as an advanced AST with a lot of description andverbose information about everything happening. This level allows the compito optimize the code to generate the most efficient possible machinecode/binary.

In the realm of IR, LLVM is the King. It stands for Low Level Virtual Machine and it operates like a "virtual" processor representation of your code. It contains registers and
everything you would expect to see in a VM.

![image](docs/img/image-15.png)

This very detailed representation is part of the compiler internal and realn once your program is compiled. This level of representation allows us toknow precisely what is going on under the hood, way more than AST.

You see me coming, we are about to leverage this to get a better view on if a bug is real or not !

## Vulnerability research crash course


![image](docs/img/image-16.png)

This code is vulnerable, it is the textbook buffer-overflow. We created a vunding the user input into it. No rocket science so far

![image](docs/img/image-17.png)

Still textbook, but this time the bug is contained in a second function calinput from main that is way bigger than what it can hold.

![image](docs/img/image-18.png)

The program is behaving like we expected, crashing in greetings when tryinger than the buffer can hold.

Let's see a third example

![image](docs/img/image-19.png)

This code contains a bug indeed, the greetings function is copying inputs wr[16] which will very rapidly overflow HOWEVER, this part of the code isNEVER reached. Yes the bug is present, yes it's a vulnerability BUT it doesn't pose any immediate threat (solid exploit primitive tho) at the moment. Let's try to catch those bugs with SemGrep !

![image](docs/img/image-20.png)

The issue with SemGrep is that as you can see if we run it against those two examples, it will flag both with the same level of importance, but as a good bug hunter what you want is
bugs you can immediately leverage so you can hopefully claim a bounty for i

This is where LLVM enter in action, it allows us to generate .ll or .bc file which can then be leverage into `Callgraph` and `Control Flow Graph`

![image](docs/img/image-21.png)
![image](docs/img/image-22.png)

Here is what the callgraph and control flow graph of our example looks like-to-function calls across a program, while a control flow graph shows the
execution flow between basic blocks within a single function. One is interpcedural.

If we analyze our vulnerable examples before in their callgraph form we can clearly see the differences by emitting a visual representation of them with Graphviz.

- Unreachable:

![image](docs/img/image-23.png)

- Reachable:

![image](docs/img/image-24.png)

Ok, call graph are done! But in real life projects, control-flow graphs can become gigantesque !

![image](docs/img/image-25.png)

Feeding that to an LLM would definitely make it buggy, we circumvent this io smaller files based on SemGrep findings.

We’re slicing them around the exact line SemGrep flagged. In practice:

- Nodes = basic blocks or individual lines of code.
- Edges = the “flow” between those blocks (who can call whom or which block

When we “slice” we start at the node for your vulnerable line, then grab evin N hops (here N = 3) in or out of it. The result is a tiny sub-graph
showing just the code paths leading into and out of that one spot, nothing

## Improving LLMs

As we saw in the beginning of this article, feeding a document to an LLM grprovides (even tho it doesn't change the furniture building instructions youdidn't respect).However, in security we often deal with dozens of files. That's where RAG cugmented Generation. Think of it like this: Instead of feeding a giganticamount of documents in a single context, which not only is limited but alsoou give it access to a library of documents it can retrieve in real-time toimprove its answer!

This allows us to provide a multitude of valuable information to our LLM, source files, SemGrep results, callgraph and control-flow-graph, template, etc.

#### What if I can't share the source code I'm auditing

This is where LLaMA comes to the rescue !
![image](docs/img/image-27.png)

Ollama is a tool for running and managing large language models (LLMs) locaifies downloading, serving, and interacting with models like LLaMA or Mistral via a simple CLI or API.

What about the files you'll tell me ? Here comes ChromaDB.
![image](docs/img/image-28.png)
It's simple, user friendly, plug and play with ollama, and it allows you too a RAG!

# Introducing: Golem                                                                                                                                                             
Golem is a tool I wrote that leverages all these components we discussed: LLM, SemGrep, LLVM, to produce an automated bug hunting tool for my fellow hackers. It flags potential security issues, generates rich graph artifacts, and leverages large-languaed, prioritized audit report, so you can find and fix critical bugs faster.

![image](docs/img/image-29.png)

How does Golem work? Basically you have to compile your project with LLVM tl then proceed to analyze the entire project directory with SemGrep. It will
then gather all the interesting files based on SemGrep finding and collect graph/cfg, and feed it to a RAG. The RAG will then analyze those files andemit a report on the validity or invalidity of the findings.

Golem supports local Ollama models and ChatGPT, it allows you to select the can add the SemGrep rules of your choices too!

Enough talk, let's run it against our examples!

![image](docs/img/image-30.png)

As we can see it correctly identified the valid bug from the invalid ones!  a complete rationale on why it classified a bug as valid or invalid:

![image](docs/img/image-31.png)

Golem produces a nice report with your valid/invalid findings, an executive summary and a conclusion. For debugging purposes it list all the files it received during the audit:

![image](docs/img/image-32.png)

You can find Golem at: https://github.com/20urc3/golem

**Happy hunting!**

### References
- https://astexplorer.net/
- https://arxiv.org/abs/2506.00054
- https://www.trychroma.com/
- https://github.com/semgrep/semgrep
- https://ollama.com/
- https://godbolt.org/
- https://mcyoung.xyz/2023/08/01/llvm-ir/

# Contributors
- Author(s): 2ourc3 - Salim LARGO
