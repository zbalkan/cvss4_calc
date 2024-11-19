import re
from typing import Optional, Tuple

import requests


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
            return "4.0", base_score, vector_string
        elif "cvssMetricV31" in metrics:
            primary_metric = metrics["cvssMetricV31"][0]["cvssData"]
            vector_string = primary_metric.get("vectorString")
            base_score = primary_metric.get("baseScore")
            print(
                f"CVSS 3.1 Base Vector: {vector_string} | Base Score: {base_score}")
            return "3.1", base_score, vector_string
        else:
            print(f"No CVSS vector available for {cve_id}.")
            return None

    except requests.RequestException as e:
        print(f"Error fetching CVSS data: {e}")
        return None


def calculate_environmental_score(base_score: float, components: dict) -> float:
    """
    Calculate the tailored (environmental) score based on the modified vector components.
    """
    impact_map = {"N": 0.0, "L": 0.22, "H": 0.56}

    # Calculate modified impact
    mc = impact_map[components["MVC"]]
    mi = impact_map[components["MVI"]]
    ma = impact_map[components["MVA"]]

    modified_impact = 1 - (1 - mc) * (1 - mi) * (1 - ma)
    modified_impact = max(modified_impact, 0)

    # Adjust the base score using modified impact
    environmental_score = base_score * modified_impact
    return round(environmental_score, 1)


def update_cvss_vector(base_vector: Optional[str], base_score: float) -> Optional[Tuple[str, float]]:
    """
    Prompt the user to update CVSS metrics for their specific environment and calculate the tailored score.
    """
    if not base_vector:
        print("No base vector found. Cannot proceed.")
        return None

    components = {item.split(":")[0]: item.split(":")[1]
                  for item in base_vector.split("/")}

    print("\n### Tailoring CVSS Vector to Your Environment ###")

    components["AV"] = determine_attack_vector(components["AV"])
    components["AC"] = determine_attack_complexity(components["AC"])
    components["PR"] = determine_privileges_required(components["PR"])
    components["UI"] = determine_user_interaction(components["UI"])
    components["MVC"] = determine_impact("Confidentiality", components["VC"])
    components["MVI"] = determine_impact("Integrity", components["VI"])
    components["MVA"] = determine_impact("Availability", components["VA"])

    tailored_vector = "/".join(f"{k}:{v}" for k, v in components.items())
    tailored_score = calculate_environmental_score(base_score, components)
    return tailored_vector, tailored_score


def main() -> None:
    print("### CVSS Tailoring Tool ###")
    cve_id = input("Enter the CVE ID (e.g., CVE-2024-1234): ").strip()

    match = re.match(r"^CVE-\d{4}-\d{4,}$", cve_id)
    if not match:
        print("Invalid CVE ID format. Please enter a valid CVE ID (e.g., CVE-2024-1234).")
        return

    base_data = fetch_cvss_base_vector(cve_id)
    if not base_data:
        print(f"Failed to fetch CVE data for {cve_id}. Exiting.")
        return

    cvss_version, base_score, base_vector = base_data

    tailored_data = update_cvss_vector(base_vector, base_score)
    if tailored_data:
        tailored_vector, tailored_score = tailored_data
        print("\n### Final Report ###")
        print(f"CVE: {cve_id}")
        print(f"CVSS Version: {cvss_version}")
        print(f"Base Score: {base_score}")
        print(f"Base Vector: {base_vector}")
        print(f"Tailored Vector: {tailored_vector}")
        print(f"Tailored Score: {tailored_score}")


if __name__ == "__main__":
    main()
