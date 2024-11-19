from typing import Optional

import requests

from utils import trim_cvss_vector


class Nvd:

    def __init__(self) -> None:
        self.__api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="

    def get_cve(self, cve_id) -> Optional[tuple[str, float, str]]:
        url = self.__api_url + cve_id
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                print(f"No vulnerabilities found for {cve_id}.")
                return None

            metrics = vulnerabilities[0].get("cve", {}).get("metrics", {})
            if "cvssMetricV40" in metrics:
                primary_metric = metrics["cvssMetricV40"][0]["cvssData"]
                vector_string = trim_cvss_vector(primary_metric.get(
                    "vectorString"))
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
