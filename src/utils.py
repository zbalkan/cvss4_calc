import re


def vector_to_dict(vector: str) -> dict[str, str]:
    """
    Converts a CVSS base vector string into a dictionary.

    Args:
        vector (str): The CVSS base vector string in the format "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".

    Returns:
        dict[str, str]: A dictionary where the keys are the metric abbreviations and the values are their corresponding ratings.
    """
    return dict(item.split(":") for item in vector.split("/")[1:])


def dict_to_vector(vector_dict: dict[str, str]) -> str:
    """
    Converts a dictionary of CVSS vector components to a CVSS vector string.

    Args:
        vector_dict (dict[str, str]): A dictionary where keys are CVSS metric names and values are their corresponding values.

    Returns:
        str: A CVSS vector string in the format "CVSS:4.0/<metric1>:<value1>/<metric2>:<value2>/...".
    """
    return "CVSS:4.0/" + \
        "/".join(f"{k}:{v}" for k, v in vector_dict.items())


def trim_cvss_vector(vector: str) -> str:
    """
    Args:
        vector (str): The CVSS vector string to be cleaned.

    Returns:
        str: The cleaned CVSS vector string with any instances of '/<metric>:X' removed.
    """

    return re.sub(r"\/(\w+:X)", "", vector)
