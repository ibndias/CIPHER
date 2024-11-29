import json, re, os, glob
import logging

logger = logging.getLogger(__name__)

def read_json_file(file_path):
    with open(file_path, "r") as file:
        flow = json.load(file)

    split_index_foothold = next(
        index
        for index, item in enumerate(flow)
        if "foothold" in item and item["foothold"]
    )

    before_foothold_flow = flow[: split_index_foothold + 1]

    split_index_root = next(
        index for index, item in enumerate(flow) if "root" in item and item["root"]
    )
    after_foothold_flow = flow[split_index_foothold + 1 : split_index_root + 1]

    logger.info("Before Foothold:")
    logger.debug(json.dumps(before_foothold_flow, indent=4))

    logger.info("After Foothold:")
    logger.debug(json.dumps(after_foothold_flow, indent=4))
    return before_foothold_flow, after_foothold_flow, flow


def parse_last_code_block(text):
    """
    Parses the last code block from the given text.

    Args:
        text (str): The text to parse.

    Returns:
        str or None: The content of the last code block, or None if no code block is found.
    """
    # Define the regular expression pattern to match code blocks
    # pattern = r"```(?:[a-zA-Z]+)?\n([\s\S]+?)\n```"
    # Update pattern to allow for optional whitespace after the opening and closing triple backticks
    pattern = r"```(?:\s*[a-zA-Z]*)?\n([\s\S]+?)\n\s*```"

    # Find all matches of the pattern in the text
    matches = re.findall(pattern, text)

    # Extract the content of the last code block
    if matches:
        last_code_block_content = matches[-1]
        # Check if multiline command
        if "\n" in last_code_block_content:
            # Wrap with triple quotes
            # last_code_block_content = f'"""\n{last_code_block_content}\n"""'
            return last_code_block_content
        else:
            return last_code_block_content
    else:
        return None
    
def open_matched_file(output_dir, test_model):
    """
    Find and open a file in the specified directory that matches the pattern *_{test_model}_FARR_results.json,
    ignoring the timestamp part of the filename.

    Parameters:
    output_dir (str): The directory where the files are located.
    test_model (str): The test model part of the filename.

    Returns:
    dict: The contents of the JSON file if found, otherwise None.
    """
    # Construct the file pattern
    file_pattern = os.path.join(output_dir, f"*_{test_model}_FARR_results.json")
    logger.debug(f"File pattern: {file_pattern}")
    # Find the file matching the pattern
    matched_files = glob.glob(file_pattern)
    logger.debug(f"Matched files: {matched_files}")
    if len(matched_files) == 1:
        file_path = matched_files[0]
        # Open and read the JSON file
        with open(file_path, "r") as file:
            data = json.load(file)
            return data
    else:
        logger.error(f"Error: Expected exactly one matching file, found {len(matched_files)}")
        return None