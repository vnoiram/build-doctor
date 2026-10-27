import json


def render(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2) + "\n"
