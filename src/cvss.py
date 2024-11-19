class CVSSVector:

    cvss_lookup_global = {
        "000000": 10,
        "000001": 9.9,
        "000010": 9.8,
        "000011": 9.5,
        "000020": 9.5,
        "000021": 9.2,
        "000100": 10,
        "000101": 9.6,
        "000110": 9.3,
        "000111": 8.7,
        "000120": 9.1,
        "000121": 8.1,
        "000200": 9.3,
        "000201": 9,
        "000210": 8.9,
        "000211": 8,
        "000220": 8.1,
        "000221": 6.8,
        "001000": 9.8,
        "001001": 9.5,
        "001010": 9.5,
        "001011": 9.2,
        "001020": 9,
        "001021": 8.4,
        "001100": 9.3,
        "001101": 9.2,
        "001110": 8.9,
        "001111": 8.1,
        "001120": 8.1,
        "001121": 6.5,
        "001200": 8.8,
        "001201": 8,
        "001210": 7.8,
        "001211": 7,
        "001220": 6.9,
        "001221": 4.8,
        "002001": 9.2,
        "002011": 8.2,
        "002021": 7.2,
        "002101": 7.9,
        "002111": 6.9,
        "002121": 5,
        "002201": 6.9,
        "002211": 5.5,
        "002221": 2.7,
        "010000": 9.9,
        "010001": 9.7,
        "010010": 9.5,
        "010011": 9.2,
        "010020": 9.2,
        "010021": 8.5,
        "010100": 9.5,
        "010101": 9.1,
        "010110": 9,
        "010111": 8.3,
        "010120": 8.4,
        "010121": 7.1,
        "010200": 9.2,
        "010201": 8.1,
        "010210": 8.2,
        "010211": 7.1,
        "010220": 7.2,
        "010221": 5.3,
        "011000": 9.5,
        "011001": 9.3,
        "011010": 9.2,
        "011011": 8.5,
        "011020": 8.5,
        "011021": 7.3,
        "011100": 9.2,
        "011101": 8.2,
        "011110": 8,
        "011111": 7.2,
        "011120": 7,
        "011121": 5.9,
        "011200": 8.4,
        "011201": 7,
        "011210": 7.1,
        "011211": 5.2,
        "011220": 5,
        "011221": 3,
        "012001": 8.6,
        "012011": 7.5,
        "012021": 5.2,
        "012101": 7.1,
        "012111": 5.2,
        "012121": 2.9,
        "012201": 6.3,
        "012211": 2.9,
        "012221": 1.7,
        "100000": 9.8,
        "100001": 9.5,
        "100010": 9.4,
        "100011": 8.7,
        "100020": 9.1,
        "100021": 8.1,
        "100100": 9.4,
        "100101": 8.9,
        "100110": 8.6,
        "100111": 7.4,
        "100120": 7.7,
        "100121": 6.4,
        "100200": 8.7,
        "100201": 7.5,
        "100210": 7.4,
        "100211": 6.3,
        "100220": 6.3,
        "100221": 4.9,
        "101000": 9.4,
        "101001": 8.9,
        "101010": 8.8,
        "101011": 7.7,
        "101020": 7.6,
        "101021": 6.7,
        "101100": 8.6,
        "101101": 7.6,
        "101110": 7.4,
        "101111": 5.8,
        "101120": 5.9,
        "101121": 5,
        "101200": 7.2,
        "101201": 5.7,
        "101210": 5.7,
        "101211": 5.2,
        "101220": 5.2,
        "101221": 2.5,
        "102001": 8.3,
        "102011": 7,
        "102021": 5.4,
        "102101": 6.5,
        "102111": 5.8,
        "102121": 2.6,
        "102201": 5.3,
        "102211": 2.1,
        "102221": 1.3,
        "110000": 9.5,
        "110001": 9,
        "110010": 8.8,
        "110011": 7.6,
        "110020": 7.6,
        "110021": 7,
        "110100": 9,
        "110101": 7.7,
        "110110": 7.5,
        "110111": 6.2,
        "110120": 6.1,
        "110121": 5.3,
        "110200": 7.7,
        "110201": 6.6,
        "110210": 6.8,
        "110211": 5.9,
        "110220": 5.2,
        "110221": 3,
        "111000": 8.9,
        "111001": 7.8,
        "111010": 7.6,
        "111011": 6.7,
        "111020": 6.2,
        "111021": 5.8,
        "111100": 7.4,
        "111101": 5.9,
        "111110": 5.7,
        "111111": 5.7,
        "111120": 4.7,
        "111121": 2.3,
        "111200": 6.1,
        "111201": 5.2,
        "111210": 5.7,
        "111211": 2.9,
        "111220": 2.4,
        "111221": 1.6,
        "112001": 7.1,
        "112011": 5.9,
        "112021": 3,
        "112101": 5.8,
        "112111": 2.6,
        "112121": 1.5,
        "112201": 2.3,
        "112211": 1.3,
        "112221": 0.6,
        "200000": 9.3,
        "200001": 8.7,
        "200010": 8.6,
        "200011": 7.2,
        "200020": 7.5,
        "200021": 5.8,
        "200100": 8.6,
        "200101": 7.4,
        "200110": 7.4,
        "200111": 6.1,
        "200120": 5.6,
        "200121": 3.4,
        "200200": 7,
        "200201": 5.4,
        "200210": 5.2,
        "200211": 4,
        "200220": 4,
        "200221": 2.2,
        "201000": 8.5,
        "201001": 7.5,
        "201010": 7.4,
        "201011": 5.5,
        "201020": 6.2,
        "201021": 5.1,
        "201100": 7.2,
        "201101": 5.7,
        "201110": 5.5,
        "201111": 4.1,
        "201120": 4.6,
        "201121": 1.9,
        "201200": 5.3,
        "201201": 3.6,
        "201210": 3.4,
        "201211": 1.9,
        "201220": 1.9,
        "201221": 0.8,
        "202001": 6.4,
        "202011": 5.1,
        "202021": 2,
        "202101": 4.7,
        "202111": 2.1,
        "202121": 1.1,
        "202201": 2.4,
        "202211": 0.9,
        "202221": 0.4,
        "210000": 8.8,
        "210001": 7.5,
        "210010": 7.3,
        "210011": 5.3,
        "210020": 6,
        "210021": 5,
        "210100": 7.3,
        "210101": 5.5,
        "210110": 5.9,
        "210111": 4,
        "210120": 4.1,
        "210121": 2,
        "210200": 5.4,
        "210201": 4.3,
        "210210": 4.5,
        "210211": 2.2,
        "210220": 2,
        "210221": 1.1,
        "211000": 7.5,
        "211001": 5.5,
        "211010": 5.8,
        "211011": 4.5,
        "211020": 4,
        "211021": 2.1,
        "211100": 6.1,
        "211101": 5.1,
        "211110": 4.8,
        "211111": 1.8,
        "211120": 2,
        "211121": 0.9,
        "211200": 4.6,
        "211201": 1.8,
        "211210": 1.7,
        "211211": 0.7,
        "211220": 0.8,
        "211221": 0.2,
        "212001": 5.3,
        "212011": 2.4,
        "212021": 1.4,
        "212101": 2.4,
        "212111": 1.2,
        "212121": 0.5,
        "212201": 1,
        "212211": 0.3,
        "212221": 0.1,
    }

    # Max severity distances
    max_severity = {
        "eq1": {0: 1, 1: 4, 2: 5},
        "eq2": {0: 1, 1: 2},
        "eq3eq6": {
            0: {0: 7, 1: 6},
            1: {0: 8, 1: 8},
            2: {1: 10}
        },
        "eq4": {0:6, 1:5, 2:4},
        "eq5": {0:1, 1:1, 2:1}
    }

    # Metric levels for severity distances
    metric_levels = {
        "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
        "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
        "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
        "AC": {"L": 0.0, "H": 0.1},
        "AT": {"N": 0.0, "P": 0.1},
        "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
        "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
        "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
        "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
        "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
        "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
        "E":  {"A": 0.0, "P": 0.1, "U": 0.2}
    }

    # Expected metric order and valid values
    expected_metric_order = {
        # Base metrics
        "AV": ["N", "A", "L", "P"],
        "AC": ["L", "H"],
        "AT": ["N", "P"],
        "PR": ["N", "L", "H"],
        "UI": ["N", "P", "A"],
        "VC": ["H", "L", "N"],
        "VI": ["H", "L", "N"],
        "VA": ["H", "L", "N"],
        "SC": ["H", "L", "N"],
        "SI": ["H", "L", "N"],
        "SA": ["H", "L", "N"],
        # Threat metrics
        "E": ["X", "A", "P", "U"],
        # Environmental metrics
        "CR": ["X", "H", "M", "L"],
        "IR": ["X", "H", "M", "L"],
        "AR": ["X", "H", "M", "L"],
        "MAV": ["X", "N", "A", "L", "P"],
        "MAC": ["X", "L", "H"],
        "MAT": ["X", "N", "P"],
        "MPR": ["X", "N", "L", "H"],
        "MUI": ["X", "N", "P", "A"],
        "MVC": ["X", "H", "L", "N"],
        "MVI": ["X", "H", "L", "N"],
        "MVA": ["X", "H", "L", "N"],
        "MSC": ["X", "H", "L", "N"],
        "MSI": ["X", "S", "H", "L", "N"],
        "MSA": ["X", "S", "H", "L", "N"],
        # Supplemental metrics (not used in scoring)
        "S": ["X", "N", "P"],
        "AU": ["X", "N", "Y"],
        "R": ["X", "A", "U", "I"],
        "V": ["X", "D", "C"],
        "RE": ["X", "L", "M", "H"],
        "U": ["X", "Clear", "Green", "Amber", "Red"],
    }

    def __init__(self, vector_string: str) -> None:
        self.__vector_string = vector_string
        self.__metrics = {}
        self.__parse_vector()
        self.__macro_vector_result = self.__compute_macro_vector()
        self.__score = self.__calculate_score()

    def __parse_vector(self) -> None:
        # Remove the "CVSS:4.0/" prefix if present
        if self.__vector_string.startswith('CVSS:4.0/'):
            vector_body = self.__vector_string[9:]
        else:
            vector_body = self.__vector_string

        # Split the vector into metric pairs
        metric_pairs = vector_body.split('/')

        for pair in metric_pairs:
            if ':' not in pair:
                continue
            metric, value = pair.split(':', 1)
            # Validate metric
            if metric not in self.expected_metric_order:
                continue
            # Validate value
            if value not in self.expected_metric_order[metric]:
                continue
            self.__metrics[metric] = value

    def __get_metric_value(self, metric: str) -> str:
        """
        Return the selected value for a given metric, applying default values as per the specification.

        Parameters:
        metric (str): The metric for which the value is to be retrieved.

        Returns:
        str: The selected value for the given metric.
        """
        # Return the selected value for a metric, applying default values as per JS code
        selected = self.__metrics.get(metric, 'X')

        # If E=X it will default to the worst case i.e. E=A
        if metric == "E" and selected == "X":
            return "A"
        # If CR=X, IR=X or AR=X they will default to the worst case i.e. H
        if metric in ["CR", "IR", "AR"] and selected == "X":
            return "H"

        # All other environmental metrics just overwrite base score values,
        # so if they’re not defined just use the base score value.
        if "M" + metric in self.__metrics:
            modified_selected = self.__metrics["M" + metric]
            if modified_selected != "X":
                return modified_selected

        return selected

    def __compute_macro_vector(self) -> str:
        # Compute EQ1
        AV = self.__get_metric_value("AV")
        PR = self.__get_metric_value("PR")
        UI = self.__get_metric_value("UI")
        if AV == "N" and PR == "N" and UI == "N":
            eq1 = "0"
        elif (AV == "N" or PR == "N" or UI == "N") and not (AV == "N" and PR == "N" and UI == "N") and AV != "P":
            eq1 = "1"
        elif AV == "P" or not (AV == "N" or PR == "N" or UI == "N"):
            eq1 = "2"
        else:
            eq1 = "2"  # Default case

        # Compute EQ2
        AC = self.__get_metric_value("AC")
        AT = self.__get_metric_value("AT")
        if AC == "L" and AT == "N":
            eq2 = "0"
        else:
            eq2 = "1"

        # Compute EQ3
        VC = self.__get_metric_value("VC")
        VI = self.__get_metric_value("VI")
        VA = self.__get_metric_value("VA")
        if VC == "H" and VI == "H":
            eq3 = "0"
        elif not (VC == "H" and VI == "H") and (VC == "H" or VI == "H" or VA == "H"):
            eq3 = "1"
        elif not (VC == "H" or VI == "H" or VA == "H"):
            eq3 = "2"
        else:
            eq3 = "2"  # Default case

        # Compute EQ4
        MSI = self.__get_metric_value("MSI")
        MSA = self.__get_metric_value("MSA")
        SC = self.__get_metric_value("SC")
        SI = self.__get_metric_value("SI")
        SA = self.__get_metric_value("SA")
        if MSI == "S" or MSA == "S":
            eq4 = "0"
        elif not (MSI == "S" or MSA == "S") and (SC == "H" or SI == "H" or SA == "H"):
            eq4 = "1"
        elif not (MSI == "S" or MSA == "S") and not (SC == "H" or SI == "H" or SA == "H"):
            eq4 = "2"
        else:
            eq4 = "2"  # Default case

        # Compute EQ5
        E = self.__get_metric_value("E")
        if E == "A":
            eq5 = "0"
        elif E == "P":
            eq5 = "1"
        elif E == "U":
            eq5 = "2"
        else:
            eq5 = "2"  # Default case

        # Compute EQ6
        CR = self.__get_metric_value("CR")
        IR = self.__get_metric_value("IR")
        AR = self.__get_metric_value("AR")
        if (CR == "H" and VC == "H") or (IR == "H" and VI == "H") or (AR == "H" and VA == "H"):
            eq6 = "0"
        else:
            eq6 = "1"

        macro_vector = eq1 + eq2 + eq3 + eq4 + eq5 + eq6
        return macro_vector

    def __calculate_score(self) -> float:
        # Step 1: Retrieve Base Score
        value = self.cvss_lookup_global.get(self.__macro_vector_result, None)
        if value is None:
            raise ValueError("Macro Vector code not found in lookup table")

        # Step 2: Compute Severity Distances
        severity_distances = {}

        # Assign severity distances for each metric
        def __get_severity_distance(metric, selected_value, highest_value):
            levels = self.metric_levels.get(metric, {})
            return levels.get(selected_value, 0) - levels.get(highest_value, 0)

        # Highest possible values in the Macro Vector (to be determined)
        # For simplicity, we'll assume the highest severity levels
        highest_metrics = {
            "AV": "N",
            "PR": "N",
            "UI": "N",
            "AC": "L",
            "AT": "N",
            "VC": "H",
            "VI": "H",
            "VA": "H",
            "SC": "H",
            "SI": "S",
            "SA": "S",
            "CR": "H",
            "IR": "H",
            "AR": "H",
            "E": "A"
        }

        # Compute severity distances for relevant metrics
        severity_distances['eq1'] = sum([
            __get_severity_distance("AV", self.__get_metric_value("AV"), highest_metrics["AV"]),
            __get_severity_distance("PR", self.__get_metric_value("PR"), highest_metrics["PR"]),
            __get_severity_distance("UI", self.__get_metric_value("UI"), highest_metrics["UI"])
        ])

        severity_distances['eq2'] = sum([
            __get_severity_distance("AC", self.__get_metric_value("AC"), highest_metrics["AC"]),
            __get_severity_distance("AT", self.__get_metric_value("AT"), highest_metrics["AT"])
        ])

        severity_distances['eq3eq6'] = sum([
            __get_severity_distance("VC", self.__get_metric_value("VC"), highest_metrics["VC"]),
            __get_severity_distance("VI", self.__get_metric_value("VI"), highest_metrics["VI"]),
            __get_severity_distance("VA", self.__get_metric_value("VA"), highest_metrics["VA"]),
            __get_severity_distance("CR", self.__get_metric_value("CR"), highest_metrics["CR"]),
            __get_severity_distance("IR", self.__get_metric_value("IR"), highest_metrics["IR"]),
            __get_severity_distance("AR", self.__get_metric_value("AR"), highest_metrics["AR"])
        ])

        severity_distances['eq4'] = sum([
            __get_severity_distance("SC", self.__get_metric_value("SC"), highest_metrics["SC"]),
            __get_severity_distance("SI", self.__get_metric_value("SI"), highest_metrics["SI"]),
            __get_severity_distance("SA", self.__get_metric_value("SA"), highest_metrics["SA"])
        ])

        severity_distances['eq5'] = __get_severity_distance("E", self.__get_metric_value("E"), highest_metrics["E"])

        # Step 3: Calculate Available Distances
        available_distances = {}

        eq1 = int(self.__macro_vector_result[0])
        available_distances['eq1'] = self.max_severity['eq1'].get(eq1, 0)

        eq2 = int(self.__macro_vector_result[1])
        available_distances['eq2'] = self.max_severity['eq2'].get(eq2, 0)

        eq3 = int(self.__macro_vector_result[2])
        eq6 = int(self.__macro_vector_result[5])
        available_distances['eq3eq6'] = self.max_severity['eq3eq6'].get(
            eq3, {}).get(eq6, 0)

        eq4 = int(self.__macro_vector_result[3])
        available_distances['eq4'] = self.max_severity['eq4'].get(eq4, 0)

        eq5 = int(self.__macro_vector_result[4])
        available_distances['eq5'] = self.max_severity['eq5'].get(eq5, 0)

        # Step 4: Compute Proportional Severity Distances
        normalized_severity = {}
        n_existing_lower = 0
        for eq in ['eq1', 'eq2', 'eq3eq6', 'eq4', 'eq5']:
            if eq == 'eq3eq6':
                # For 'eq3eq6', we need to access both eq3 and eq6
                eq3 = int(self.__macro_vector_result[2])
                eq6 = int(self.__macro_vector_result[5])
                max_severity_eq_value = self.max_severity[eq][eq3][eq6]
            else:
                index = int(self.__macro_vector_result[int(eq[-1]) - 1])
                max_severity_eq_value = self.max_severity[eq][index]

            max_severity_eq = max_severity_eq_value * 0.1

            if available_distances.get(eq) and max_severity_eq > 0:
                proportion = severity_distances[eq] / max_severity_eq
                normalized_severity[eq] = available_distances[eq] * proportion
                n_existing_lower += 1
            else:
                normalized_severity[eq] = 0

        # Step 5: Adjust the Score
        if n_existing_lower > 0:
            mean_distance = sum(normalized_severity.values()) / n_existing_lower
        else:
            mean_distance = 0

        adjusted_score = value - mean_distance
        if adjusted_score < 0:
            adjusted_score = 0.0
        if adjusted_score > 10:
            adjusted_score = 10.0

        # Round the adjusted score to one decimal place
        final_score = round(adjusted_score * 10) / 10.0

        return final_score

    def get_score(self) -> float:
        return self.__score

    def get_severity(self) -> str:
        if self.__score == 0.0:
            return "None"
        elif self.__score < 4.0:
            return "Low"
        elif self.__score < 7.0:
            return "Medium"
        elif self.__score < 9.0:
            return "High"
        else:
            return "Critical"

    def get_vector_str(self) -> str:
        return self.__vector_string

    def get_nomenclature(self) -> str:
        """
        Determine the CVSS nomenclature based on the metrics provided.
        Returns one of 'CVSS-B', 'CVSS-BT', 'CVSS-BE', or 'CVSS-BTE'.
        """
        # Determine if Threat metrics are defined (i.e., have values other than 'X')
        threat_metrics = ['E']
        has_threat = any(
            self.__metrics.get(metric, 'X') != 'X' and self.__metrics.get(
                metric) != 'X'
            for metric in threat_metrics
        )

        # Determine if Environmental metrics are defined
        environmental_metrics = [
            'CR', 'IR', 'AR',
            'MAV', 'MAC', 'MAT', 'MPR', 'MUI',
            'MVC', 'MVI', 'MVA',
            'MSC', 'MSI', 'MSA'
        ]
        has_environmental = any(
            self.__metrics.get(metric, 'X') != 'X' and self.__metrics.get(
                metric) != 'X'
            for metric in environmental_metrics
        )

        # Start with base nomenclature
        nomenclature = 'CVSS-B'

        # Append 'T' if Threat metrics are included
        if has_threat:
            nomenclature += 'T'

        # Append 'E' if Environmental metrics are included
        if has_environmental:
            nomenclature += 'E'

        return nomenclature
