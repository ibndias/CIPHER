from huggingface_hub import InferenceClient
from openai import OpenAI
import os
from typing import Any, Optional

# Get API keys from environment variables
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY")

# Initialize OpenAI client
openai_client = OpenAI(base_url="https://api.openai.com/v1", api_key=OPENAI_API_KEY)

# Initialize OpenRouter client
openrouter_client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=OPENROUTER_API_KEY)

def model_generate(
    modelselector: str,
    message: str,
    temperature: float = 0.01,
    stream: bool = True,
    debug: bool = False,
    mode: str = "response",
) -> str:
    """
    Generate model response based on the model selector and mode.
    """
    model_function_map = {
        "gpt-3.5-turbo": openai_generate,
        "gpt-4-turbo": openai_generate,
        "gpt-4o": openai_generate,
        "gpt-4o-mini": openai_generate,
        "meta-llama/llama-3.1-405b-instruct:free": openrouter_generate,
    }

    generate_function = model_function_map.get(modelselector)
    if not generate_function:
        raise ValueError(f"Model '{modelselector}' not found.")

    if mode == "eval":
        system_message = "You are a helpful assistant."
    elif mode == "response":
        system_message = "You are a helpful penetration testing assistant."
    else:
        raise ValueError(f"Mode '{mode}' not supported.")

    return generate_function(message, system_message, modelselector, temperature, stream, debug)

def openrouter_generate(
    message: str,
    system_message: str = "You are a helpful penetration testing assistant.",
    model: str = "meta-llama/llama-3.1-405b-instruct:free",
    temperature: float = 0.01,
    stream: bool = True,
    debug: bool = False,
) -> str:
    """
    Generate response using OpenRouter.
    """
    chat_completion = openrouter_client.chat.completions.create(
        model=model,
        temperature=temperature,
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": message},
        ],
        stream=stream,
        max_tokens=3000,
    )

    msg_buffer = ""
    if stream:
        for message in chat_completion:
            if message.choices[0].finish_reason is None:
                msg_buffer += message.choices[0].delta.content
                print(message.choices[0].delta.content, end="")
            else:
                break
    return msg_buffer

def openai_generate(
    message: str,
    system_message: str = "You are a helpful penetration testing assistant.",
    model: str = "gpt-4o-mini",
    temperature: float = 0.01,
    stream: bool = True,
    debug: bool = False,
) -> str:
    """
    Generate response using OpenAI.
    """
    chat_completion = openai_client.chat.completions.create(
        model=model,
        temperature=temperature,
        messages=[
            {"role": "system", "content": system_message},
            {"role": "user", "content": message},
        ],
        stream=stream,
        max_tokens=3000,
    )

    msg_buffer = ""
    if stream:
        for message in chat_completion:
            if message.choices[0].finish_reason is None:
                msg_buffer += message.choices[0].delta.content
            else:
                break
    return msg_buffer
