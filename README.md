# CIPHER
CIPHER is an abbreviation of Cybersecurity Intelligent Pentesting Helper for Ethical Researcher

This is the official repo for [CIPHER Paper](https://www.mdpi.com/1424-8220/24/21/6878).

CIPHER is a large language model fine-tuned specifically to guide beginners to penetrate into target machines with expert reasoning. Penetration testing is a complex task that can not be mastered quickly. Most of beginner starts their journey by asking others or experts, mostly for a hints or nudges. This will keep going until they can develop their own out-of-the-box reasoning, gained from experience.

We believed that experience is the best teacher, and penetration testing can not be mastered just by reading the book or literature. Even the technique is written in multiple sources such as Hacktricks, PayloadAllTheThings, ExploitDB, etc., the out of the box reasoning process happens inside penetration tester brain is undocumented, except in their writeups. And this is where CIPHER focused. CIPHER trained from experience-based knowledge gained from experts writeups.

## Dataset Augmentation

TBD (Check the paper if you are curious)

## FARR Flow
Findings, Action, Reasoning, Result (FARR) Flow is a methodology to augments information from existing writeups as compact as possible. Most of penetration tester, including the experts documents their progress in a writeups.

However, there is no standards on how these writeups formatted. Therefore, the goal is to capture an ordered dynamics information gathered in penetration testing process which is written as natural language writeups.

### What is exactly FARR?

1. `Findings`: Anything that has been found in the penetration testing process.
2. `Action`: Action that is taken after `Findings` is acknowledged, and taken based on `Reasoning`.
3. `Reasoning`: The rationale behind `Action`, the reason that is mostly absent in beginner knowledge.
4. `Result`: Summarizing the outcomes of the actions taken, including any successful exploits and their impact.

# Project Structure
The project is organized into the following directories:
- `generation/`: Contains scripts to generate FARR Flow.
- `evaluation/`: Contains scripts to evaluate LLMs using previously generated FARR Flow.

# Quick Start
## FARR Flow Generation
To generate FARR Flow, follow these steps:
1. Clone the repository:
    ```sh
    git clone https://github.com/ibndias/CIPHER.git
    ```
2. Navigate to the project directory:
    ```sh
    cd CIPHER/farr-generation
    ```
3. Generate Pentesting Flow
    Generate a pentesting flow from a directories of input files.

    ```bash
    python main.py generate ./source/htb-0xdf ./output/htb-0xdf-flow
    ```
    Optional arguments:

    - `--api_key`: OpenAI API key (default: uses `OPENAI_API_KEY` environment variable)
    - `--api_base`: OpenAI API base URL (default: `https://api.openai.com/v1`)
    - `--model_chosen`: OpenAI model to use (default: `gpt-4o-mini`)
    - `--chunk_size`: Chunk size for text splitting (default: 8000)
    - `--chunk_overlap`: Chunk overlap for text splitting (default: 1000)
    
4. Parse Flow Files
    Parse pentesting flow files into JSON format.

    ```bash
    python main.py parse ./output/htb-0xdf-flow ./output/htb-0xdf-flow-json
    ```
5. Mark Footholds
    Mark footholds in parsed flow files using the OpenAI API.

    ```bash
    python main.py mark ./output/htb-0xdf-flow-json ./output/htb-0xdf-flow-json-foothold
    ```
    Optional arguments:
    - `--api_key`: OpenAI API key (default: uses `OPENAI_API_KEY` environment variable)
    - `--api_base`: OpenAI API base URL (default: `https://api.openai.com/v1`)
    - `--model_chosen`: OpenAI model to use (default: `gpt-4`)

It will results in three directory containing different format.
- `./output/htb-0xdf-flow` will contains the raw unprocessed FARR Flow.
- `./output/htb-0xdf-flow-json` will contains the parsed FARR Flow. This file is enough to evaluate LLMs with FARR Flow evaluation.
- `./output/htb-0xdf-flow-json-foothold` contains the same JSON but with added foothold and root keys, which informing the step where the foothold and root is obtained. This will be useful for future FARR Flow evaluation to measure how much foothold and root obtained.

## FARR Flow Evaluation

After we have the FARR Flow JSON files. Proceed with the evaluation steps below:

TBD

## Expert Conversation Dataset Augmentation
TBD
# Contributing
We welcome contributions to improve CIPHER and its evaluation framework. Please follow these steps to contribute:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit your changes and push them to your fork.
4. Create a pull request with a detailed description of your changes.

# Citing
```tex
@Article{s24216878,
AUTHOR = {Pratama, Derry and Suryanto, Naufal and Adiputra, Andro Aprila and Le, Thi-Thu-Huong and Kadiptya, Ahmada Yusril and Iqbal, Muhammad and Kim, Howon},
TITLE = {CIPHER: Cybersecurity Intelligent Penetration-Testing Helper for Ethical Researcher},
JOURNAL = {Sensors},
VOLUME = {24},
YEAR = {2024},
NUMBER = {21},
ARTICLE-NUMBER = {6878},
URL = {https://www.mdpi.com/1424-8220/24/21/6878},
PubMedID = {39517776},
ISSN = {1424-8220},
DOI = {10.3390/s24216878}
}
```

# Contact
For any questions or inquiries, please contact us at [derryprata@gmail.com](mailto:email@example.com).