import json


def load_events(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            events = json.load(file)

    except FileNotFoundError:
        raise FileNotFoundError(
            f"Security event file not found: {file_path}"
        )

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON format in {file_path}: "
            f"line {error.lineno}, column {error.colno}"
        )

    if not isinstance(events, list):
        raise ValueError(
            "The security event dataset must contain a JSON list."
        )

    return events