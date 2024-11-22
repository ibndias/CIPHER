
import openai
from openai import OpenAI


def initialize_openai_client(api_key, api_base):
    client = OpenAI(api_key=api_key, base_url=api_base)
    return client

def gpt(client, model_chosen, systemprompt, userprompt, stream=False):
    response = client.chat.completions.create(
        model=model_chosen,
        max_tokens=8192,
        temperature=0,
        messages=[{"role": "user", "content": userprompt}],
        stream=stream,
    )
    if stream:
        for chunk in response:
            if chunk.choices[0].delta.content is not None:
                print(chunk.choices[0].delta.content, end="")
    return response.choices[0].message.content