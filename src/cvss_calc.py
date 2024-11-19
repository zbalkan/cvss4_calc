import re
from typing import Optional, Tuple

import requests

from cvss import CVSSVector


def __get_metric_input(metric_name: str, question: str, options: dict) -> str:
    """
    Helper function to get input for a specific metric with a default value.
    """

    default = 'X'
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


def determine_m_attack_vector() -> str:
    options = {
        "N": {"description": "Network (exploited via a remote network, e.g., the Internet)."},
        "A": {"description": "Adjacent (limited to a logically adjacent topology, e.g., Bluetooth)."},
        "L": {"description": "Local (requires local access or login)."},
        "P": {"description": "Physical (requires physical access to the device)."},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        "Modified Attack Vector (MAV)",
        "Where can the attacker exploit the vulnerability?",
        options,
    )


def determine_m_attack_complexity() -> str:
    options = {
        "L": {"description": "Low (no specialized conditions required)."},
        "H": {"description": "High (requires overcoming extra controls)."},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        "Attack Complexity (AC)",
        "How complex is the attack?",
        options,
    )


def determine_m_attack_requirements() -> str:
    options = {
        "N": {"description": "None (The successful attack does not depend on the deployment and execution conditions of the vulnerable system)"},
        "P": {"description": "Present (The successful attack depends on the presence of specific deployment and execution conditions)"},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        "Modified Attack Requirements (MAT)",
        "How complex is the attack?",
        options,
    )

def determine_m_privileges_required() -> str:
    options = {
        "N": {"description": "None (no privileges required)."},
        "L": {"description": "Low (user-level privileges required)."},
        "H": {"description": "High (administrator-level privileges required)."},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        "Privileges Required (MPR)",
        "What privileges does the attacker need?",
        options,
    )


def determine_m_user_interaction() -> str:
    options = {
        "N": {"description": "None (no user interaction required)."},
        "P": {"description": "Passive (limited user interaction required)."},
        "A": {"description": "Active (requires targeted user interaction)."},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        "User Interaction (MUI)",
        "Does the attack require user interaction?",
        options,
    )

def determine_vuln_sys_impact(metric_name: str) -> str:
    options = {
        "N": {"description": "None (no impact)."},
        "L": {"description": "Low (limited impact)."},
        "H": {"description": "High (serious impact)."},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        f"Vulnerable System {metric_name} Impact",
        f"How does the vulnerability impact {metric_name.lower()} of vulnerable system(s)?",
        options,
    )


def determine_sub_sys_confidentiality() -> str:
    options = {
        "N": {"description": "Negligible (no impact)."},
        "L": {"description": "Low (limited impact)."},
        "H": {"description": "High (serious impact)."},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        f"Subsequent System Confidentiality Impact",
        f"How does the vulnerability impact confidentiality of subsequent system(s)?",
        options,
    )


def determine_sub_sys_impact(metric_name: str) -> str:
    options = {
        "N": {"description": "Negligible (no impact)."},
        "L": {"description": "Low (limited impact)."},
        "H": {"description": "High (serious impact)."},
        "S": {"description": "Safety (OT/ICS, human life at risk)."},
        "X": {"description": "Not Defined."},
    }
    return __get_metric_input(
        f"Subsequent System {metric_name} Impact",
        f"How does the vulnerability impact {metric_name.lower()} of subsequent system(s)?",
        options,
    )


def determine_environmental_sec_requirement(metric_name: str) -> str:
    options = {
        "L": {"description": "Low (minimal importance)."},
        "M": {"description": "Medium (moderate importance)."},
        "H": {"description": "High (critical importance)."},
        "X": {"description": "Not Defined."},
    }

    return __get_metric_input(
        f"Environmental Security Requirement: {metric_name}",
        f"How important is {metric_name.lower()} to your environment?",
        options,
    )


def determine_exploit_maturity() -> str:
    options = {
        "X": {"description": "Not Defined."},
        "A": {"description": "Attacked (known exploitation)."},
        "P": {"description": "POC (Proof-of-Concept exists, no knowledge of exploit attempts)."},
        "U": {"description": "Unreported (No known POC or exploitation)."},
    }
    return __get_metric_input(
        "Exploit Maturity (E)",
        "What is the status of exploitation accorfing to threat intel?",
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

    # Update Environmental (Modified Base Metrics)
    ## Exploitability Metrics
    vector_dict["MAV"] = determine_m_attack_vector()
    vector_dict["MAC"] = determine_m_attack_complexity()
    vector_dict["MAT"] = determine_m_attack_requirements()
    vector_dict["MPR"] = determine_m_privileges_required()
    vector_dict["MUI"] = determine_m_user_interaction()

    # Vulnerable System Impact Metrics
    vector_dict["MVC"] = determine_vuln_sys_impact("Confidentiality")
    vector_dict["MVI"] = determine_vuln_sys_impact("Integrity")
    vector_dict["MVA"] = determine_vuln_sys_impact("Availability")

    # Subsequent System Impact Metrics
    vector_dict["MSC"] = determine_sub_sys_confidentiality()
    vector_dict["MSI"] = determine_sub_sys_impact("Integrity")
    vector_dict["MSA"] = determine_sub_sys_impact("Availability")

    # Update Environmental (Security Requirements)
    vector_dict["CR"] = determine_environmental_sec_requirement(
        "Confidentiality")
    vector_dict["IR"] = determine_environmental_sec_requirement(
        "Integrity")
    vector_dict["AR"] = determine_environmental_sec_requirement(
        "Availability")

    # Threat Metrics
    vector_dict["E"] = determine_exploit_maturity()

    tailored_vector = "CVSS:4.0/" + \
        "/".join(f"{k}:{v}" for k, v in vector_dict.items())
    cvss_vector = CVSSVector(tailored_vector)

    return cvss_vector

def clean_vector(vector:str) -> str:
    """
    Clean up the CVSS vector string by removing any whitespace and converting to uppercase.
    """
    return re.sub(r"\/(\w+:X)", "", vector)

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
    print(f"Base Vector: {clean_vector(base_vector)}")
    print(f"Base Score: {base_score}")
    print(f"Tailored Vector: {clean_vector(tailored_vector.get_vector_str())}")
    print(f"Tailored Nomenclature: {tailored_vector.get_nomenclature()}")
    print(f"Tailored Score: {tailored_vector.get_score()}")
    print(f"Tailored Severity: {tailored_vector.get_severity()}")

if __name__ == "__main__":
    main()
