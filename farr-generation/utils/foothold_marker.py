import json
import os
import datetime
import ast
import openai
from openai import OpenAI
import argparse

# Constants
RUNSTAMP = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

def gpt(system_prompt, user_prompt, client, model_name, stream=False, debug=False):
    """
    Generates a response from the GPT model.

    Args:
        system_prompt (str): The system prompt for the GPT model.
        user_prompt (str): The user prompt for the GPT model.
        client (OpenAI): The OpenAI client.
        model_name (str): The name of the GPT model to use.
        stream (bool): Whether to stream the response.
        debug (bool): Whether to print debug information.

    Returns:
        str: The response from the GPT model.
    """
    if debug:
        print("\033[1;32;40m")
        print("GPT System Prompt: ", system_prompt)
        print("GPT User Prompt: ", user_prompt)
        print("\033[0;37;40m")
    
    response = client.chat.completions.create(
        model=model_name,
        max_tokens=100,
        temperature=0,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        stream=stream
    )
    
    if stream:
        for chunk in response:
            if chunk.choices[0].delta.content is not None:
                print(chunk.choices[0].delta.content, end='')
    else:
        response = response.choices[0].message.content
    
    if debug:
        print(response)
    
    return response

def append_to_file(file_path, data):
    """
    Appends data to a JSON file.

    Args:
        file_path (str): The path to the JSON file.
        data (dict): The data to append.
    """
    try:
        with open(file_path, "r") as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        existing_data = []

    existing_data.append(data)

    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    with open(file_path, "w") as file:
        json.dump(existing_data, file, ensure_ascii=False, indent=4)

def parse_foothold(filepath, output_dir, client, model_name):
    """
    Parses the JSON file and detects foothold and root access.

    Args:
        filepath (str): The path to the JSON file.
        output_dir (str): The directory to save the output files.
        client (OpenAI): The OpenAI client.
        model_name (str): The name of the GPT model to use.
    """
    file_name = os.path.basename(filepath)
    output_file_path = os.path.join(output_dir, file_name)
    
    if os.path.exists(output_file_path):
        print(f"File {file_name} already processed, skipping...")
        return
    
    with open(filepath, 'r') as f:
        data = json.load(f)

    print("Processing item: ")
    full_info = ""
    for index, item in enumerate(data):
        print(f"{index},", end="")
        print(item)
        finding = item['Findings']
        action = item['Action']
        reasoning = item['Reasoning']
        result = item['Result']
        full_info += f"{index + 1}. {finding}, {action}, {reasoning}, {result}\n"
        
    detected_foothold = gpt(
        "You are a helpful penetration testing assistant", 
        f"""{full_info}

        Foothold gained at line number?
        Root access gained at line number?
        Answer in format (foothold_line_number, root_access_line_number)""",
        client,
        model_name,
        stream=False
    )
    
    try:
        line_numbers = ast.literal_eval(detected_foothold)
        foothold_line_number = line_numbers[0] - 1
        root_access_line_number = line_numbers[1] - 1
    except (SyntaxError, ValueError):
        print("Invalid input string")
        return

    for index, item in enumerate(data):
        if index == foothold_line_number:
            item.update({"foothold": True})
        if index == root_access_line_number:
            item.update({"root": True})

        append_to_file(output_file_path, item)

    print(f"Done, file saved to {output_file_path}")

def mark_foothold_folder(directory, output_dir, client, model_name):
    """
    Processes all files in the given directory.

    Args:
        directory (str): The directory containing the files to process.
        output_dir (str): The directory to save the output files.
        client (OpenAI): The OpenAI client.
        model_name (str): The name of the GPT model to use.
    """
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        print(f"Processing {file_path}")
        parse_foothold(file_path, output_dir, client, model_name)

def foothold_mark_generator():
    parser = argparse.ArgumentParser(description="Foothold Mark Generator")
    parser.add_argument("source_dir", help="Directory containing the source JSON files")
    parser.add_argument("output_dir", help="Directory to save the foothold marked output JSON files")
    parser.add_argument("--model_name", default="gpt-4", help="GPT model name to use")
    parser.add_argument("--api_base", default="https://api.openai.com/v1", help="OpenAI API endpoint")
    parser.add_argument("--api_key", default=os.environ.get("OPENAI_API_KEY"), help="OpenAI API key")
    args = parser.parse_args()

    client = OpenAI(api_key=args.api_key, base_url=args.api_base)

    mark_foothold_folder(args.source_dir, args.output_dir, client, args.model_name)