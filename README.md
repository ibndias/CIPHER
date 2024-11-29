# CIPHER
CIPHER is an abbreviation of Cybersecurity Intelligent Pentesting Helper for Ethical Researcher

This is the official repo for [CIPHER Paper](https://www.mdpi.com/1424-8220/24/21/6878).

CIPHER is a large language model fine-tuned specifically to guide beginners to penetrate into target machines with expert reasoning. Penetration testing is a complex task that can not be mastered quickly. Most of beginner starts their journey by asking others or experts, mostly for a hints or nudges. This will keep going until they can develop their own out-of-the-box reasoning, gained from experience.

We believed that experience is the best teacher, and penetration testing can not be mastered just by reading the book or literature. Even the technique is written in multiple sources such as Hacktricks, PayloadAllTheThings, ExploitDB, etc., the out of the box reasoning process happens inside penetration tester brain is undocumented, except in their writeups. And this is where CIPHER focused. CIPHER trained from experience-based knowledge gained from experts writeups.

> TLDR: CIPHER is an LLM fine tuned for penetration testing guidance. CIPHER knowledge is based on writeups augmented into expert conversation. While FARR Flow is a method to measure the guidance accuracy for LLM by utilizing existing writeups.

# Quick Start

## 1. Clone the repository:
    ```sh
    git clone https://github.com/ibndias/CIPHER.git
    ```
## 2. Generate FARR Flow

We have two vulnerable machine writeups example from 0xdf blogs [HTB Aero](https://0xdf.gitlab.io/2023/09/28/htb-aero.html) and [HTB Analytics](https://0xdf.gitlab.io/2024/03/23/htb-analytics.html). Both are already available inside `/farr-generation/source/htb-0xdf-small` directory in markdown format. 

Let's generate FARR Flows based on these writeups:

```sh
cd CIPHER/farr-generation
python farr-gen.py full ./source/htb-0xdf-small ./output/htb-0xdf-small-flow
```

Now the FARR Flows is generated and saved in `./output/htb-0xdf-small-flow-foothold`.

## 3. Evaluate the model

Once we have the FARR Flows, we can start evaluating our model. For this example, we will evaluate `gpt-3.5-turbo` performance on [HTB Aero](https://0xdf.gitlab.io/2023/09/28/htb-aero.html) and [HTB Analytics](https://0xdf.gitlab.io/2024/03/23/htb-analytics.html) vulnerable machines with `gpt-4o-mini` as evaluator.

The criteria that we measure is `service`. The score would represent how accurate the model in guiding user to penetrate the target based on the `service` accuracy:

Go to evaluation directory:
```sh
cd ../farr-evaluation
```
Generate the `gpt-3.5-turbo` response:
```
python farr-eval.py --test-model gpt-3.5-turbo --mode response --flow-dir ../farr-generation/output/htb-0xdf-small-flow-foothold --output-dir ./output-response-small
```
Evaluate the `gpt-3.5-turbo` response with `gpt-4o-mini` model based on `service` criteria:
```
python farr-eval.py --test-model gpt-3.5-turbo --mode eval --eval-model gpt-4o-mini --flow-dir ../farr-generation/output/htb-0xdf-small-flow-foothold --response-dir ./output-response-small --output-dir ./output-eval-small-service --criteria service
```
Get the average score:

```
python scoring.py ./output-eval-small-service 
```

Now you get the average score of the model performance based on two vulnerable machines by `service` accuracy. In the paper we use three accuracy (`service`, `vulnerability`, `outcome`). To evaluate for different criteria, you can modify the `--criteria` arguments. To add your custom LLM inference endpoints, modify the `farr-evaluation/utils/inference.py`.


## Dataset Augmentation

TODO: Explain

(Check the [paper](https://www.mdpi.com/1424-8220/24/21/6878) if you are curious)

### Expert Guidance Conversation
![expert-conversation](./assets/expert-conv.png)
### Conversation Augmentation Pipeline
![expert-conversation-pipeline](./assets/expert-conv-pipeline.png)

## FARR Flow
Findings, Action, Reasoning, Result (FARR) Flow is a methodology to augments information from existing writeups as compact as possible. Most of penetration tester, including the experts documents their progress in a writeups.

### Pipeline
![farr-flow-gen-pipeline](./assets/farr-flow-gen-pipeline.png)

### Augmentation Example
![farr-flow-gen-pipeline-example](./assets/farr-flow-gen-pipeline-example.png)

However, there is no standards on how these writeups formatted. Therefore, the goal is to capture an ordered dynamics information gathered in penetration testing process which is written as natural language writeups.

### What is exactly FARR?

1. `Findings`: Anything that has been found in the penetration testing process.
2. `Action`: Action that is taken after `Findings` is acknowledged, and taken based on `Reasoning`.
3. `Reasoning`: The rationale behind `Action`, the reason that is mostly absent in beginner knowledge.
4. `Result`: Summarizing the outcomes of the actions taken, including any successful exploits and their impact.

# Project Structure
The project is organized into the following directories:
- `./farr-generation/`: Contains scripts to generate FARR Flow from writeups.
- `./farr-evaluation/`: Contains scripts to evaluate LLMs using previously generated FARR Flow.


## FARR Flow Generation

To generate FARR Flow from the writeups that we have, follow these steps:

1. Generate Pentesting Flow
    Generate a pentesting flow from a directories of input files.

    ```sh
    python farr-gen.py generate ./source/htb-0xdf ./output/htb-0xdf-flow
    ```
    Optional arguments:

    - `--api-key`: OpenAI API key (default: uses `OPENAI_API_KEY` environment variable)
    - `--api-base`: OpenAI API base URL (default: `https://api.openai.com/v1`)
    - `--model-chosen`: OpenAI model to use (default: `gpt-4o-mini`)
    - `--chunk-size`: Chunk size for text splitting (default: 8000)
    - `--chunk-overlap`: Chunk overlap for text splitting (default: 1000)
    
2. Parse Flow Files
    Parse pentesting flow files into JSON format.

    ```sh
    python farr-gen.py parse ./output/htb-0xdf-flow ./output/htb-0xdf-flow-json
    ```
3. Mark Footholds
    Mark footholds in parsed flow files using the OpenAI API.

    ```sh
    python farr-gen.py mark ./output/htb-0xdf-flow-json ./output/htb-0xdf-flow-json-foothold
    ```
    Optional arguments:
    - `--api-key`: OpenAI API key (default: uses `OPENAI_API_KEY` environment variable)
    - `--api-base`: OpenAI API base URL (default: `https://api.openai.com/v1`)
    - `--model-chosen`: OpenAI model to use (default: `gpt-4`)

It will results in three directory containing different format.
- `./output/htb-0xdf-flow` will contains the raw unprocessed FARR Flow.
- `./output/htb-0xdf-flow-json` will contains the parsed FARR Flow.
- `./output/htb-0xdf-flow-json-foothold` contains the FARR Flow with added foothold and root keys, which informing the step where the foothold and root is obtained. This is useful for FARR Flow evaluation in the future to measure how much foothold and root obtained.

## 2. FARR Flow Evaluation

FARR Flow evaluates the response from the model based on the current findings. It uses open-ended question formulated from FARR steps, asking for the next correct action to be taken.

Since the question is open-ended, FARR uses three criteria to measure the model answer quality, based on the relevance and similarity of three aspects: vulnerability, outcome, and service.

![farr-flow-evaluation](./assets/farr-flow-evaluation.png)

After we have the FARR Flow JSON files. Proceed with the evaluation steps below:

### Generating Model Answer/Response
```sh
python farr-eval.py --test-model gpt-4o-mini --mode response --flow-dir ../../farr-generation/output/htb-0xdf-flow-foothold --output-dir ./output-response
```

### Evaluating Model Answer/Response
```sh
python farr-eval.py --test-model gpt-4o-mini --mode eval --eval-model gpt-4o-mini --flow-dir ../../farr-generation/output/htb-0xdf-flow-foothold --response-dir ./output-response --output-dir ./output-eval-service --criteria service
```

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