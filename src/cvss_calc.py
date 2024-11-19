import re
from typing import Optional, Tuple

import requests

from cvss import CVSSVector


def get_yes_no_input(prompt: str) -> bool:
    """
    Helper function to get validated yes/no input from the user.
    """
    while True:
        response: str = input(prompt).strip().lower()
        if response in ["y", "yes"]:
            return True
        elif response in ["n", "no"]:
            return False
        else:
            print("Invalid input. Please enter 'Y' or 'N'.")


def get_metric_input(metric_name: str, question: str, default: str, options: dict) -> str:
    """
    Helper function to get input for a specific metric with a default value.
    """
    print(f"\n### {metric_name} ###")
    print(f"Default: {default}")
    for key, value in options.items():
        print(f"{key}: {value['description']}")
    while True:
        response = input(f"{question} [{default}]: ").strip().upper()
        if response == "":
            print(f"Keeping default: {default}")
            return default
        elif response in options:
            print(f"Selected: {options[response]['description']}")
            return response
        else:
            print("Invalid input. Please select from the available options.")


def determine_attack_vector(default: str) -> str:
    options = {
        "N": {"description": "Network (exploited via a remote network, e.g., the Internet)."},
        "A": {"description": "Adjacent (limited to a logically adjacent topology, e.g., Bluetooth)."},
        "L": {"description": "Local (requires local access or login)."},
        "P": {"description": "Physical (requires physical access to the device)."},
    }
    return get_metric_input(
        "Attack Vector (AV)",
        "Where can the attacker exploit the vulnerability?",
        default,
        options,
    )


def determine_attack_complexity(default: str) -> str:
    options = {
        "L": {"description": "Low (no specialized conditions required)."},
        "H": {"description": "High (requires overcoming extra controls)."},
    }
    return get_metric_input(
        "Attack Complexity (AC)",
        "How complex is the attack?",
        default,
        options,
    )


def determine_privileges_required(default: str) -> str:
    options = {
        "N": {"description": "None (no privileges required)."},
        "L": {"description": "Low (user-level privileges required)."},
        "H": {"description": "High (administrator-level privileges required)."},
    }
    return get_metric_input(
        "Privileges Required (PR)",
        "What privileges does the attacker need?",
        default,
        options,
    )


def determine_user_interaction(default: str) -> str:
    options = {
        "N": {"description": "None (no user interaction required)."},
        "P": {"description": "Passive (limited user interaction required)."},
        "A": {"description": "Active (requires targeted user interaction)."},
    }
    return get_metric_input(
        "User Interaction (UI)",
        "Does the attack require user interaction?",
        default,
        options,
    )


def determine_impact(metric_name: str, default: str) -> str:
    options = {
        "N": {"description": "None (no impact)."},
        "L": {"description": "Low (limited impact)."},
        "H": {"description": "High (serious impact)."},
    }
    return get_metric_input(
        f"{metric_name} Impact",
        f"How does the vulnerability impact {metric_name.lower()}?",
        default,
        options,
    )


def determine_environmental_requirement(metric_name: str, default: str) -> str:
    """
    Prompt the user to provide the environmental requirement for a given metric.

    Parameters:
        metric_name (str): The name of the metric (e.g., "Confidentiality").
        default (str): The default value for the metric (typically 'X').

    Returns:
        str: The selected value ('L', 'M', 'H', or 'X').
    """
    options = {
        "L": {"description": "Low (minimal importance)."},
        "M": {"description": "Medium (moderate importance)."},
        "H": {"description": "High (critical importance)."},
        "X": {"description": "Not Defined."},
    }

    return get_metric_input(
        f"{metric_name} Requirement",
        f"How important is {metric_name.lower()} to your environment?",
        default,
        options,
    )


def determine_exploit_maturity(default: str) -> str:
    """
    Prompt the user to select the Exploit Maturity (E) value.
    """
    options = {
        "X": {"description": "Not Defined."},
        "P": {"description": "Proof-of-Concept exists (reduced likelihood of exploitation)."},
        "F": {"description": "Functional exploit exists (moderate likelihood of exploitation)."},
        "H": {"description": "High likelihood of exploitation."},
    }
    return get_metric_input(
        "Exploit Maturity (E)",
        "What is the maturity level of available exploits?",
        default,
        options,
    )


def fetch_cvss_base_vector(cve_id: str) -> Optional[Tuple[str, float, str]]:
    """
    Fetch the CVSS base vector for a given CVE ID from NVD.
    """
    print(f"Fetching CVSS base vector for {cve_id}...")
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(api_url, timeout=30)
        response.raise_for_status()
        data = response.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            print(f"No vulnerabilities found for {cve_id}.")
            return None

        metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
        if "cvssMetricV40" in metrics:
            primary_metric = metrics["cvssMetricV40"][0]["cvssData"]
            vector_string = primary_metric.get("vectorString")
            base_score = primary_metric.get("baseScore")
            print(
                f"CVSS 4.0 Base Vector: {vector_string} | Base Score: {base_score}")
            return vector_string, base_score, "4.0"
        else:
            print(f"No CVSS 4.0 vector available for {cve_id}.")
            return None

    except requests.RequestException as e:
        print(f"Error fetching CVSS data: {e}")
        return None


def update_cvss_vector(base_vector: str) -> CVSSVector:
    """
    Prompt the user to update CVSS metrics for their specific environment and calculate the tailored score.

    If no environmental metrics are defined (all 'X'), return the base score.
    """
    vector_dict = dict(item.split(":") for item in base_vector.split("/")[1:])

    # Update metrics
    vector_dict["AV"] = determine_attack_vector(vector_dict["AV"])
    vector_dict["AC"] = determine_attack_complexity(vector_dict["AC"])
    vector_dict["PR"] = determine_privileges_required(vector_dict["PR"])
    vector_dict["UI"] = determine_user_interaction(vector_dict["UI"])
    vector_dict["MVC"] = determine_impact("Confidentiality", vector_dict["VC"])
    vector_dict["MVI"] = determine_impact("Integrity", vector_dict["VI"])
    vector_dict["MVA"] = determine_impact("Availability", vector_dict["VA"])

    # Update environmental requirements
    vector_dict["CR"] = determine_environmental_requirement(
        "Confidentiality", vector_dict.get("CR", "X"))
    vector_dict["IR"] = determine_environmental_requirement(
        "Integrity", vector_dict.get("IR", "X"))
    vector_dict["AR"] = determine_environmental_requirement(
        "Availability", vector_dict.get("AR", "X"))
    vector_dict["E"] = determine_exploit_maturity(vector_dict.get("E", "X"))

    tailored_vector = "CVSS:4.0/" + \
        "/".join(f"{k}:{v}" for k, v in vector_dict.items())
    cvss_vector = CVSSVector(tailored_vector)

    return cvss_vector


def main() -> None:
    print("### CVSS 4.0 Tailoring Tool ###")
    cve_id = input("Enter the CVE ID (e.g., CVE-2024-1234): ").strip()

    match = re.match(r"^CVE-\d{4}-\d{4,}$", cve_id)
    if not match:
        print("Invalid CVE ID format. Please enter a valid CVE ID (e.g., CVE-2024-1234).")
        return

    base_data = fetch_cvss_base_vector(cve_id)
    if not base_data:
        print(f"Failed to fetch CVE data for {cve_id}. Exiting.")
        return

    base_vector, base_score, cvss_version = base_data
    tailored_vector = update_cvss_vector(base_vector)

    print("\n### Final Report ###")
    print(f"CVE: {cve_id}")
    print(f"CVSS Version: {cvss_version}")
    print(f"Base Vector: {base_vector}")
    print(f"Base Score: {base_score}")
    print(f"Tailored Vector: {tailored_vector.get_vector_str()}")
    print(f"Tailored Nomenclature: {tailored_vector.get_nomenclature()}")
    print(f"Tailored Score: {tailored_vector.get_score()}")
    print(f"Tailored Severity: {tailored_vector.get_severity()}")

if __name__ == "__main__":
    main()
