# Author: Derry Pratama (ibndias)
# Date: 2023-10-05
# Description: FARR Flow Generator

import os
import argparse
from openai import OpenAI
from utils.flow_processing import generate_pentesting_flow_folder, parse_flow_folder
from utils.foothold_marker import mark_foothold_folder

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="FARR Flow Generator and Parser",
        epilog="""
        Examples:
        Generate pentesting flow:
            python main.py generate /path/to/input/folder /path/to/output/folder
        Parse flow files:
            python main.py parse /path/to/input/folder /path/to/output/folder
        """
    )
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for generating pentesting flow
    generate_parser = subparsers.add_parser("generate", help="Generate pentesting flow from files in a folder")
    generate_parser.add_argument("folder", type=str, help="Folder containing the input files")
    generate_parser.add_argument("dest_folder", type=str, help="Folder to save the generated flow files")
    generate_parser.add_argument("--api-key", type=str, default=os.getenv("OPENAI_API_KEY"), help="API key for OpenAI. By default, uses the OPENAI_API_KEY environment variable")
    generate_parser.add_argument("--api-base", type=str, default="https://api.openai.com/v1", help="API base URL for OpenAI. By default, uses the OpenAI API base URL")
    generate_parser.add_argument("--model-chosen", type=str, default="gpt-4o-mini", help="Model to use for OpenAI API")
    generate_parser.add_argument("--chunk-size", type=int, default=8000, help="Chunk size for text splitting")
    generate_parser.add_argument("--chunk-overlap", type=int, default=1000, help="Chunk overlap for text splitting")

    # Subparser for parsing flow files
    parse_parser = subparsers.add_parser("parse", help="Parse flow files and save as JSON")
    parse_parser.add_argument("input_folder", type=str, help="Folder containing the input files")
    parse_parser.add_argument("output_folder", type=str, help="Folder where the JSON files will be saved")

    # Subparser for marking footholds
    mark_parser = subparsers.add_parser("mark", help="Mark footholds in flow files")
    mark_parser.add_argument("input_folder", type=str, help="Folder containing the input files")
    mark_parser.add_argument("output_folder", type=str, help="Folder where the marked files will be saved")
    mark_parser.add_argument("--api-key", type=str, default=os.getenv("OPENAI_API_KEY"), help="API key for OpenAI. By default, uses the OPENAI_API_KEY environment variable")
    mark_parser.add_argument("--api-base", type=str, default="https://api.openai.com/v1", help="API base URL for OpenAI. By default, uses the OpenAI API base URL")
    mark_parser.add_argument("--model-chosen", type=str, default="gpt-4", help="Model to use for OpenAI API")

    # Subparser for full process (generate, parse, mark)
    full_parser = subparsers.add_parser("full", help="Generate, parse, and mark footholds in one go")
    full_parser.add_argument("folder", type=str, help="Folder containing the input files")
    full_parser.add_argument("dest_folder", type=str, help="Folder to save the generated flow files")
    full_parser.add_argument("--api-key", type=str, default=os.getenv("OPENAI_API_KEY"), help="API key for OpenAI. By default, uses the OPENAI_API_KEY environment variable")
    full_parser.add_argument("--api-base", type=str, default="https://api.openai.com/v1", help="API base URL for OpenAI. By default, uses the OpenAI API base URL")
    full_parser.add_argument("--model-chosen", type=str, default="gpt-4o-mini", help="Model to use for OpenAI API")
    full_parser.add_argument("--chunk-size", type=int, default=8000, help="Chunk size for text splitting")
    full_parser.add_argument("--chunk-overlap", type=int, default=1000, help="Chunk overlap for text splitting")

    args = parser.parse_args()

    if args.command == "generate":
        print("[+] Start generating pentesting flow...")
        generate_pentesting_flow_folder(args.api_key, args.api_base, args.folder, args.dest_folder, args.model_chosen, args.chunk_size, args.chunk_overlap)
        print("[+] Finished generating pentesting flow. All flow files saved in the output folder: " + args.dest_folder)
        # Ask user if they want to parse the generated flow files
        parse = input("[?] Do you want to parse the generated flow files now? (y/n): ")
        if parse.lower() == "y":
            print("[+] Start parsing flow files...")
            parse_flow_folder(args.dest_folder, args.dest_folder + "-json")
            print("[+] Finished parsing flow files.")
            # Ask user if they want to mark footholds in the parsed flow files
            mark = input("[?] Do you want to mark footholds in the parsed flow files now? (y/n): ")
            if mark.lower() == "y":
                print("[+] Start marking footholds in flow files...")
                mark_foothold_folder(args.dest_folder + "-json", args.dest_folder + "-foothold", OpenAI(api_key=args.api_key, base_url=args.api_base), args.model_chosen)
                print("[+] Finished marking footholds in flow files.")
            else:
                print("[+] OK! You can mark the parsed flow files later using the 'mark' command. Example: python main.py mark " + args.dest_folder + "-json " + args.dest_folder + "-foothold")
        else:
            print("[+] OK! You can parse the generated flow files later using the 'parse' command. Example: python main.py parse " + args.dest_folder + " /path/to/output/folder")
    elif args.command == "parse":
        print("[+] Start parsing flow files...")
        parse_flow_folder(args.input_folder, args.output_folder)
        print("[+] Finished parsing flow files.")
    elif args.command == "mark":
        print("[+] Start marking footholds in flow files...")
        mark_foothold_folder(args.input_folder, args.output_folder, OpenAI(api_key=args.api_key, base_url=args.api_base), args.model_chosen)
        print("[+] Finished marking footholds in flow files.")
    elif args.command == "full":
        print("[+] Start generating pentesting flow...")
        generate_pentesting_flow_folder(args.api_key, args.api_base, args.folder, args.dest_folder, args.model_chosen, args.chunk_size, args.chunk_overlap)
        print("[+] Finished generating pentesting flow. All flow files saved in the output folder: " + args.dest_folder)
        print("[+] Start parsing flow files...")
        parse_flow_folder(args.dest_folder, args.dest_folder + "-json")
        print("[+] Finished parsing flow files.")
        print("[+] Start marking footholds in flow files...")
        mark_foothold_folder(args.dest_folder + "-json", args.dest_folder + "-foothold", OpenAI(api_key=args.api_key, base_url=args.api_base), args.model_chosen)
        print("[+] Finished marking footholds in flow files.")
        # Explain directory structure
        print("[+] Outputs are here:")
        print("    - Generated flow files: " + args.dest_folder)
        print("    - Parsed flow files: " + args.dest_folder + "-json")
        print("    - Marked with foothold flow files: " + args.dest_folder + "-foothold")
