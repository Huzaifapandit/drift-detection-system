
# text_drift_detector.py

# Function to read file content safely
def read_file(file_name):
    try:
        with open(file_name, "r") as file:
            content = file.readlines()
        return content
    except FileNotFoundError:
        print("File not found:", file_name)
        return []
    except Exception as e:
        print(f"Error reading {file_name}: {e}")
        return []

# Function to parse lines into key-value pairs (dictionary format)
def parse_config(lines):
    config_dict = {}
    for line in lines:
        line = line.strip()
        # Ignore empty lines and comments
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            config_dict[key.strip()] = value.strip()
    return config_dict

# Function to compare baseline and current configuration
def compare_configs(baseline, current):
    changes = {"modified": [], "missing": [], "new": []}
    
    # Check for modified or missing entries in baseline
    for key in baseline:
        if key not in current:
            changes["missing"].append((key, baseline[key]))
        elif baseline[key] != current[key]:
            changes["modified"].append((key, baseline[key], current[key]))
    
    # Check for new entries in the current file
    for key in current:
        if key not in baseline:
            changes["new"].append((key, current[key]))

    return changes

# Function to categorize the drift based on predefined rules
def categorize_drift(drift_data):
    categories = {"security": [], "monitoring": [], "operational": [], "governance": []}
    
    # Categorization rules (based on key names)
    for drift_type in drift_data:
        for entry in drift_data[drift_type]:
            key = entry[0]
            if "ENCRYPT" in key or "AUTH" in key or "MFA" in key:
                categories["security"].append(entry)
            elif "LOG" in key or "MONITOR" in key or "ALERT" in key:
                categories["monitoring"].append(entry)
            elif "TIMEOUT" in key or "RETRY" in key or "CACHE" in key:
                categories["operational"].append(entry)
            elif "OWNER" in key or "ROLE" in key or "APPROVAL" in key:
                categories["governance"].append(entry)
            else:
                categories["operational"].append(entry)  # Default category
    
    return categories

# Function to calculate the risk level based on drift categories
def calculate_risk_level(categories):
    risk_score = 0
    # Assign score based on category counts
    risk_score += len(categories["security"]) * 3  # High risk for security issues
    risk_score += len(categories["monitoring"]) * 2
    risk_score += len(categories["operational"]) * 1
    risk_score += len(categories["governance"]) * 2
    
    # Risk level logic
    if risk_score >= 15:
        return "HIGH"
    elif risk_score >= 8:
        return "MEDIUM"
    else:
        return "LOW"
    # Function to generate the drift summary report
def generate_report(changes, categories, risk_level):
    # Print to console
    print("========= DRIFT DETECTION SUMMARY =========")
    print(f"Total Entries Analyzed : {len(changes['modified']) + len(changes['missing']) + len(changes['new'])}")
    print(f"Drifted Entries        : {len(changes['modified']) + len(changes['missing']) + len(changes['new'])}")
    
    # Modified entries
    if changes["modified"]:
        print("\nMODIFIED CONFIGURATIONS:")
        for entry in changes["modified"]:
            print(f"{entry[0]} : {entry[1]} -> {entry[2]}")
    
    # Missing entries
    if changes["missing"]:
        print("\nMISSING KEYS:")
        for entry in changes["missing"]:
            print(f"{entry[0]}")
    
    # New entries
    if changes["new"]:
        print("\nNEW KEYS:")
        for entry in changes["new"]:
            print(f"{entry[0]} = {entry[1]}")
    
    # Categories
    print("\nCATEGORY COUNTS:")
    print(f"Security-Relevant: {len(categories['security'])}")
    print(f"Monitoring: {len(categories['monitoring'])}")
    print(f"Operational: {len(categories['operational'])}")
    print(f"Governance: {len(categories['governance'])}")
    
    # Risk level
    print(f"\nOverall Risk Level: {risk_level}")
    print("=========================================")

    # Write to file
    with open("drift_report.txt", "w") as file:
        file.write("========= DRIFT DETECTION SUMMARY =========\n")
        file.write(f"Total Entries Analyzed : {len(changes['modified']) + len(changes['missing']) + len(changes['new'])}\n")
        file.write(f"Drifted Entries        : {len(changes['modified']) + len(changes['missing']) + len(changes['new'])}\n")
        
        if changes["modified"]:
            file.write("\nMODIFIED CONFIGURATIONS:\n")
            for entry in changes["modified"]:
                file.write(f"{entry[0]} : {entry[1]} -> {entry[2]}\n")
        
        if changes["missing"]:
            file.write("\nMISSING KEYS:\n")
            for entry in changes["missing"]:
                file.write(f"{entry[0]}\n")
        
        if changes["new"]:
            file.write("\nNEW KEYS:\n")
            for entry in changes["new"]:
                file.write(f"{entry[0]} = {entry[1]}\n")
        
        file.write("\nCATEGORY COUNTS:\n")
        file.write(f"Security-Relevant: {len(categories['security'])}\n")
        file.write(f"Monitoring: {len(categories['monitoring'])}\n")
        file.write(f"Operational: {len(categories['operational'])}\n")
        file.write(f"Governance: {len(categories['governance'])}\n")
        
        file.write(f"\nOverall Risk Level: {risk_level}\n")
        file.write("=========================================\n")


# Main function to execute the drift detection system
def main():
    # Read files
    baseline_lines = read_file("baseline.txt")
    current_lines = read_file("current.txt")
    
    if not baseline_lines or not current_lines:
        print("Error: One or both files are missing or empty.")
        return
    
    # Parse files into dictionaries
    baseline_config = parse_config(baseline_lines)
    current_config = parse_config(current_lines)
    
    # Compare configurations
    changes = compare_configs(baseline_config, current_config)
    
    # Categorize drift
    categories = categorize_drift(changes)
    
    # Calculate risk level
    risk_level = calculate_risk_level(categories)
    
    # Generate and print report
    generate_report(changes, categories, risk_level)


# Run the main function
if __name__ == "__main__":
    main()