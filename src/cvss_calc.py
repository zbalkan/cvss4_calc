import re

from cvss import CVSSVector
from nvd import Nvd

questions = {
    "MAV": {
        "title": "(Modified) Attack Vector (MAV)",
        "question": "Where can the attacker exploit the vulnerability?",
        "options": {
            "N": "Network (exploited via a remote network, e.g., the Internet).",
            "A": "Adjacent (limited to a logically adjacent topology, e.g., Bluetooth).",
            "L": "Local (requires local access or login).",
            "P": "Physical (requires physical access to the device).",
            "X": "Not Defined.",
        },
    },
    "MAC": {
        "title": "(Modified) Attack Complexity (MAC)",
        "question": "How complex is the attack?",
        "options": {
            "L": "Low (no specialized conditions required).",
            "H": "High (requires overcoming extra controls).",
            "X": "Not Defined.",
        },
    },
    "MAT": {
        "title": "(Modified) Attack Requirements (MAT)",
        "question": "How complex is the attack?",
        "options": {
            "N": "None (The successful attack does not depend on the deployment and execution conditions of the vulnerable system).",
            "P": "Present (The successful attack depends on the presence of specific deployment and execution conditions).",
            "X": "Not Defined.",
        },
    },
    "MPR": {
        "title": "(Modified) Privileges Required (MPR)",
        "question": "What privileges does the attacker need?",
        "options": {
            "N": "None (no privileges required).",
            "L": "Low (user-level privileges required).",
            "H": "High (administrator-level privileges required).",
            "X": "Not Defined.",
        },
    },
    "MUI": {
        "title": "(Modified) User Interaction (MUI)",
        "question": "Does the attack require user interaction?",
        "options": {
            "N": "None (no user interaction required).",
            "P": "Passive (limited user interaction required).",
            "A": "Active (requires targeted user interaction).",
            "X": "Not Defined.",
        },
    },
    "MVC": {
        "title": "Vulnerable System Confidentiality Impact (MVC)",
        "question": "How does the vulnerability impact confidentiality of vulnerable system(s)?",
        "options": {
            "N": "None (no impact).",
            "L": "Low (limited impact).",
            "H": "High (serious impact).",
            "X": "Not Defined.",
        },
    },
    "MVI": {
        "title": "Vulnerable System Integrity Impact (MVI)",
        "question": "How does the vulnerability impact integrity of vulnerable system(s)?",
        "options": {
            "N": "None (no impact).",
            "L": "Low (limited impact).",
            "H": "High (serious impact).",
            "X": "Not Defined.",
        },
    },
    "MVA": {
        "title": "Vulnerable System Availability Impact (MVA)",
        "question": "How does the vulnerability impact availability of vulnerable system(s)?",
        "options": {
            "N": "None (no impact).",
            "L": "Low (limited impact).",
            "H": "High (serious impact).",
            "X": "Not Defined.",
        },
    },
    "MSC": {
        "title": "Subsequent System Confidentiality Impact (MSC)",
        "question": "How does the vulnerability impact confidentiality of subsequent system(s)?",
        "options": {
            "N": "Negligible (no impact).",
            "L": "Low (limited impact).",
            "H": "High (serious impact).",
            "X": "Not Defined.",
        },
    },
    "MSI": {
        "title": "Subsequent System Integrity Impact (MSI)",
        "question": "How does the vulnerability impact integrity of subsequent system(s)?",
        "options": {
            "N": "Negligible (no impact).",
            "L": "Low (limited impact).",
            "H": "High (serious impact).",
            "S": "Safety (OT/ICS, human life at risk).",
            "X": "Not Defined.",
        },
    },
    "MSA": {
        "title": "Subsequent System Availability Impact (MSA)",
        "question": "How does the vulnerability impact availability of subsequent system(s)?",
        "options": {
            "N": "Negligible (no impact).",
            "L": "Low (limited impact).",
            "H": "High (serious impact).",
            "S": "Safety (OT/ICS, human life at risk).",
            "X": "Not Defined.",
        },
    },
    "CR": {
        "title": "Environmental Security Requirement: Confidentiality (CR)",
        "question": "How important is confidentiality to your environment?",
        "options": {
            "L": "Low (minimal importance).",
            "M": "Medium (moderate importance).",
            "H": "High (critical importance).",
            "X": "Not Defined.",
        },
    },
    "IR": {
        "title": "Environmental Security Requirement: Integrity (IR)",
        "question": "How important is integrity to your environment?",
        "options": {
            "L": "Low (minimal importance).",
            "M": "Medium (moderate importance).",
            "H": "High (critical importance).",
            "X": "Not Defined.",
        },
    },
    "AR": {
        "title": "Environmental Security Requirement: Availability (AR)",
        "question": "How important is availability to your environment?",
        "options": {
            "L": "Low (minimal importance).",
            "M": "Medium (moderate importance).",
            "H": "High (critical importance).",
            "X": "Not Defined.",
        },
    },
    "E": {
        "title": "Exploit Maturity (E)",
        "question": "What is the status of exploitation according to threat intel?",
        "options": {
            "X": "Not Defined.",
            "A": "Attacked (known exploitation).",
            "P": "POC (Proof-of-Concept exists, no knowledge of exploit attempts).",
            "U": "Unreported (No known POC or exploitation).",
        },
    },
}

def vector_to_dict(base_vector: str) -> dict[str, str]:
    return dict(item.split(":") for item in base_vector.split("/")[1:])

def dict_to_vector(vector_dict: dict[str, str]) -> str:
    return "CVSS:4.0/" + \
        "/".join(f"{k}:{v}" for k, v in vector_dict.items())

def iterate_questions(questions: dict, vector_dict:dict) -> dict:
    """
    Loop through the questions dictionary, prompt the user for inputs,
    and update the vector dictionary with selected values.

    Parameters:
    - questions (dict): The dictionary containing the metrics, questions, and options.
    - vector_dict (dict): The dictionary to be updated with the user's input.
    """
    for metric, details in questions.items():
        # Display the metric title and question, along with available options
        print(f"\n\n### {details['title']} ###")

        for key, description in details['options'].items():
            print(f"  - {key}: {description}")

        # Get the user input
        while True:
            response = input(f"{details['question']} [X]: ").strip().upper()
            if response == "":
                print(f"Keeping default: X")
                vector_dict[metric] = "X"
                break
            elif response in details['options']:
                print(f"Selected: {details['options'][response]}")
                vector_dict[metric] = response
                break
            else:
                print("Invalid input. Please select from the available options.")
    return vector_dict

def update_cvss_vector(base_vector: str) -> CVSSVector:
    """
    Prompt the user to update CVSS metrics for their specific environment and calculate the tailored score.

    If no environmental metrics are defined (all 'X'), return the base score.
    """
    vector_dict = vector_to_dict(base_vector)
    vector_dict = iterate_questions(questions, vector_dict)
    tailored_vector = dict_to_vector(vector_dict)
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

    base_data = Nvd().get_cve(cve_id)
    if not base_data:
        print(f"Failed to fetch CVE data for {cve_id}. Exiting.")
        return

    base_vector, base_score, cvss_version = base_data
    tailored_vector = update_cvss_vector(base_vector)

    print("\n### Final Report ###")
    print(f"CVE                   : {cve_id}")
    print(f"CVSS Version          : {cvss_version}")
    print(f"Base Vector           : {clean_vector(base_vector)}")
    print(f"Base Score            : {base_score}")
    print(f"Tailored Vector       : {clean_vector(tailored_vector.get_vector_str())}")
    print(f"Tailored Nomenclature : {tailored_vector.get_nomenclature()}")
    print(f"Tailored Score        : {tailored_vector.get_score()}")
    print(f"Tailored Severity     : {tailored_vector.get_severity()}")

if __name__ == "__main__":
    main()
