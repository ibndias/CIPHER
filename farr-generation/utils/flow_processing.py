
import json
import os
import re
from langchain.text_splitter import CharacterTextSplitter
from utils.openai_utils import initialize_openai_client, gpt
from utils.file_utils import load_file, preprocess_text, prepare_output_file, save_actions
from concurrent.futures import ThreadPoolExecutor

def text_to_flow(client, filtered_text, model_chosen, chunk_size, chunk_overlap):
    text_splitter = CharacterTextSplitter.from_tiktoken_encoder(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
    )
    texts = text_splitter.split_text(filtered_text)
    actions = []
    for text in texts:
        FARR_PROMPT = """
------
Convert the above a self sufficient lists of every important actions done by the author.
Make sure to include every small details.
Just give me the list.
Follow this exact format and replace the text in the angle bracket with technical analysis:
* Findings: <what the author known/have>, Action: <action done from known information>, Reasoning: <the author do the action because of>, Result: <output/result after the action done>

EXACT EXAMPLE OUTPUT:
* Findings: IP of the target is 123.12.4.1, Action: running nmap with command nmap -p- 123.12.4.1, Reasoning: because we only know the target IP and we have to get more information about the target, Result: found port 80 and 443 open.

BEGIN!"""
        message = text + FARR_PROMPT
        resp = gpt(client, model_chosen, "", message, False).strip()
        actions.append(resp)
    return actions

# def parse_flow(text):
#     """
#     Parses structured findings text into JSON.

#     Args:
#         text (str): The input text containing structured findings.

#     Returns:
#         list: A list of dictionaries with keys Findings, Action, Reasoning, and Result.
#     """
#     def parse_entry(entry):
#         fields = ["Findings", "Action", "Reasoning", "Result"]
#         pattern = r"(" + "|".join(fields) + r"): (.*?)(?=\s*\w+:|$)"
#         matches = re.findall(pattern, entry, re.DOTALL)
#         return {key: value.strip() for key, value in matches}

#     # Split the text based on '* Findings:' markers
#     entries = re.split(r"\* (?=Findings:)", text.strip())
#     entries = [entry.strip() for entry in entries if entry.strip()]  # Clean up empty entries

#     # Parse each entry and return the result as a JSON-like structure
#     return [parse_entry(entry) for entry in entries]

def parse_flow(text):
    """
    Parses structured findings text into JSON.

    Args:
        text (str): The input text containing structured findings.

    Returns:
        list: A list of dictionaries with keys Findings, Action, Reasoning, and Result.
    """
    def parse_entry(entry):
        fields = ["Findings", "Action", "Reasoning", "Result"]
        # Ensure multiline support for field extraction
        pattern = r"(" + "|".join(fields) + r"):((?:.*?(?=\s*(?:Findings|Action|Reasoning|Result):|$)))"
        matches = re.findall(pattern, entry, re.DOTALL)
        return {key: value.strip() for key, value in matches}

    # Split the text based on '* Findings:' markers
    entries = re.split(r"\* (?=Findings:)", text.strip())
    entries = [entry.strip() for entry in entries if entry.strip()]  # Clean up empty entries
    
    # If entry does not contain one of the fields, remove it
    entries = [entry for entry in entries if all(field in entry for field in ["Findings", "Action", "Reasoning", "Result"])]

    # Parse each entry and return the result as a JSON-like structure
    return [parse_entry(entry) for entry in entries]



def parse_flow_folder(input_folder, output_folder):
    """
    Processes all files in the input folder, parses their content, and saves the output in JSON format in the output folder.

    Args:
        input_folder (str): The folder containing the input files.
        output_folder (str): The folder where the JSON files will be saved.
    """
    # Ensure output_folder exists, create if it doesn't
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    # Loop through each file in the input_folder
    for filename in os.listdir(input_folder):
        file_path = os.path.join(input_folder, filename)
        
        # Ensure it's a file
        if os.path.isfile(file_path):
            # Open and read the content of the file
            with open(file_path, 'r') as file:
                content = file.read()
                
            # Process the content through the parse_flow function
            processed_data = parse_flow(content)
            
            # Define the output file path (same name, different folder, JSON extension)
            output_file_path = os.path.join(output_folder, os.path.splitext(filename)[0] + '.json')
            
            # Save the processed data to a JSON file
            with open(output_file_path, 'w') as json_file:
                json.dump(processed_data, json_file, indent=4)

    print("[+] All flows in folder has been parsed.")
    
    
def generate_pentesting_flow(client, filepath, dest_folder, model_chosen, chunk_size, chunk_overlap, pdf=False):
    input_text = load_file(filepath, pdf)
    filtered_text = preprocess_text(input_text, pdf)
    destfilename = prepare_output_file(filepath, dest_folder)
    if os.path.exists(destfilename):
        print("[!] Skipped: "+destfilename + " already exists. Skipping ...")
        return
    actions = text_to_flow(client, filtered_text, model_chosen, chunk_size, chunk_overlap)
    save_actions(destfilename, actions)

def generate_pentesting_flow_folder(api_key, api_base, folder, dest_folder, model_chosen, chunk_size, chunk_overlap):
    client = initialize_openai_client(api_key, api_base)
    with ThreadPoolExecutor() as executor:
        futures = []
        for filename in os.listdir(folder):
            filepath = os.path.join(folder, filename)
            print("[+] Processing: " + filepath)
            futures.append(executor.submit(generate_pentesting_flow, client, filepath, dest_folder, model_chosen, chunk_size, chunk_overlap, filepath.endswith(".pdf")))
            
        print("[+] Waiting for all files to be processed...")
        for future in futures:
            future.result()  # Wait for all futures to complete
            