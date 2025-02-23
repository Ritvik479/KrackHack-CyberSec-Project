# Solution to PS 1 KrackHack
This is **Team Insaniac's** proposed solution to the first problem statement (i.e. beluga 😸) in the **KrackHack hackathon**.
---
## The Problem 🤔
Our task was to build a web web application that performs **static analysis** on uploaded files (e.g., `.exe`, `.docx`, `.pdf`), flags malicious indicators, and provides a clear verdict (“Malicious” or “Clean”). This system had to be easy to use and should offer concise results.
---
## Tech Stack 💻
+ Front-end : HTML/CSS with JS integration
+ Back-end : Flask (Python)
+ File Analaysis : Hashing algorithm and YARA rules
---
## Solution (in brief)
1. Front-end:
  + Take help of Jashnoor
2. Back-end:
  + With flask, we route the web page (`index.html`). `index.html` is a template 
  + 
  + Ensures only .exe, .pdf, and .docx files are uploaded.
  + Passes uploaded files to scan_file() for analysis.
  + Returns scan results as JSON responses.