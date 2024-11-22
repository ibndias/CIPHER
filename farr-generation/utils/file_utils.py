import os
import re
from langchain.document_loaders import UnstructuredPDFLoader

def load_file(filepath, pdf):
    if pdf:
        loader = UnstructuredPDFLoader(filepath)
        data = loader.load()
        return data[0].page_content
    else:
        with open(filepath) as f:
            return f.read()

def preprocess_text(input_text, pdf):
    if pdf:
        return remove_text_before_enumeration(input_text)
    else:
        return remove_text_before_hashtag(input_text)

def prepare_output_file(filepath, dest_folder):
    srcfilename = os.path.basename(filepath)
    destfilename = srcfilename.replace(".pdf", ".txt")
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    return os.path.join(dest_folder, destfilename)

def save_actions(destfilename, actions):
    with open(destfilename, "w") as file:
        for action in actions:
            file.write(action + "\n")

def remove_text_before_enumeration(input_string):
    pattern = re.compile(r"(?i)Enumeration\n")
    match = pattern.search(input_string)
    if match:
        index = match.start()
        return input_string[index:]
    else:
        raise ValueError("No match found in input string")

def remove_text_before_hashtag(text):
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("#"):
            return "\n".join(lines[i:])
    return text