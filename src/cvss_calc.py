import re

from cvss import CVSSv4
from nvd import Nvd
from utils import dict_to_vector, vector_to_dict

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

def iterate_questions(questions: dict, vector:str) -> str:
    """
    Loop through the questions dictionary, prompt the user for inputs,
    and update the vector dictionary with selected values.

    Parameters:
    - questions (dict): The dictionary containing the metrics, questions, and options.
    - vector_dict (dict): The dictionary to be updated with the user's input.
    """
    vector_dict: dict[str, str] = vector_to_dict(vector)
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
    return dict_to_vector(vector_dict)

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

    # Ask the questions and update the vector
    new_vector = iterate_questions(questions, base_vector)
    new_cvss = CVSSv4(new_vector)

    print("\n### Final Report ###")
    print(f"CVE                   : {cve_id}")
    print(f"CVSS Version          : {cvss_version}")
    print(f"Base Vector           : {base_vector}")
    print(f"Base Score            : {base_score}")
    print(f"Tailored Vector       : {new_cvss.get_vector()}")
    print(f"Tailored Nomenclature : {new_cvss.get_nomenclature()}")
    print(f"Tailored Score        : {new_cvss.get_score()}")
    print(f"Tailored Severity     : {new_cvss.get_severity()}")

if __name__ == "__main__":
    main()
