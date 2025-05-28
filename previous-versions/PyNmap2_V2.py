#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PyNmap Network Scanner Script with ndiff support
"""

__author__ = "Abraham Ruiz"
__email__ = "aruiz7@students.columbiabasin.edu"
__date__ = "May 28 2025"
__version__ = "1.1.0"

import os
import json
import pickle
import subprocess
import datetime
import sys

def create_logon_id_directory():
    logon_dir = "Logon ID"

    if not os.path.exists(logon_dir):
        try:
            os.makedirs(logon_dir)
            print(f"Created directory: {logon_dir}")
        except OSError as e:
            print(f"Error creating directory {logon_dir}: {e}")
            return False
    else:
        print(f"Directory {logon_dir} already exists")

    return True

def get_filename_with_date(file_type="json"):
    today = datetime.datetime.now()
    date_str = today.strftime("%m%d%y")  # mmddyy format

    if file_type.lower() == "pickle":
        return f"{date_str}.pickle"
    elif file_type.lower() == "xml":
        return f"{date_str}.xml"
    else:
        return f"{date_str}.json"

def run_nmap_scan(network="192.168.1.0/24"):
    print(f"Starting Nmap scan on network: {network}")

    # XML output file
    xml_output = os.path.join("Logon ID", get_filename_with_date("xml"))

    # Modified Nmap command to include TCP port scanning
    nmap_cmd = [
        "nmap",
        "-sT",       # TCP connect scan
        "-p 1-1000", # Scan common ports
        "--open",    # Only show open ports
        network
    ]

    try:
        # Runs Nmap command
        result = subprocess.run(nmap_cmd,
                              capture_output=True,
                              text=True,
                              timeout=600)  # 10 minute timeout

        if result.returncode == 0:
            print("Nmap scan completed successfully")
            print(f"XML results saved to: {xml_output}")
            return {
                "stdout": result.stdout,
                "xml_file": xml_output
            }
        else:
            print(f"Nmap scan failed with return code: {result.returncode}")
            print(f"Error: {result.stderr}")
            return None

    except subprocess.TimeoutExpired:
        print("Nmap scan timed out")
        return None

def find_previous_xml_scan():
    logon_dir = "Logon ID"
    xml_files = [f for f in os.listdir(logon_dir) if f.endswith('.xml')]

    # Sort files by modification time (oldest first)
    xml_files.sort(key=lambda f: os.path.getmtime(os.path.join(logon_dir, f)))

    # Return the most recent file if there are at least 2 files
    if len(xml_files) >= 2:
        return os.path.join(logon_dir, xml_files[-2])  # Returns the second newest file

    return None

def run_ndiff(previous_xml, current_xml):
    print(f"Running ndiff to compare with previous scan...")

    ndiff_cmd = [
        "ndiff",
        previous_xml,
        current_xml
    ]

    try:
        result = subprocess.run(ndiff_cmd,
                              capture_output=True,
                              text=True)

        if result.returncode == 0:
            return result.stdout
        else:
            print(f"ndiff failed with return code: {result.returncode}")
            print(f"Error: {result.stderr}")
            return None

    except Exception as e:
        print(f"Error running ndiff: {e}")
        return None

def save_scan_results(scan_data, file_type="json"):
    if not scan_data:
        print("No scan data to save")
        return False

    # Creates filename
    filename = get_filename_with_date(file_type)
    filepath = os.path.join("Logon ID", filename)

    try:
        if file_type.lower() == "pickle":
            # Saved as pickle file
            with open(filepath, 'wb') as f:
                pickle.dump(scan_data, f)
            print(f"Pickle file saved here: {filepath}")

        else:
            # Save as JSON file
            # Convert scan output to structured data for JSON
            scan_info = {
                "timestamp": datetime.datetime.now().isoformat(),
                "scan_type": "TCP Port Scan",
                "raw_output": scan_data["stdout"] if isinstance(scan_data, dict) else scan_data,
                "xml_file": scan_data.get("xml_file") if isinstance(scan_data, dict) else None,
                "file_format": "json"
            }

            with open(filepath, 'w') as f:
                json.dump(scan_info, f, indent=2)
            print(f"JSON file saved here: {filepath}")

        return True

    except Exception as e:
        print(f"Error saving file {filepath}: {e}")
        return False

def save_diff_results(diff_data):
    if not diff_data:
        print("No diff data to save")
        return False

    # Create filename for diff results
    today = datetime.datetime.now()
    date_str = today.strftime("%m%d%y")
    filename = f"diff_{date_str}.txt"
    filepath = os.path.join("Logon ID", filename)

    try:
        with open(filepath, 'w') as f:
            f.write(diff_data)
        print(f"Diff results saved to: {filepath}")
        return True
    except Exception as e:
        print(f"Error saving diff results: {e}")
        return False

def main():
    print("PyNmap Network Scanner with ndiff")
    print("*" * 40)

    # Creates Logon ID directory if needed
    if not create_logon_id_directory():
        print("Failed to create/access Logon ID directory")
        return 1

    # Get network to scan
    home_network = "192.168.1.137/24"

    print(f"Target network: {home_network}")

    # Runs Nmap scan
    scan_results = run_nmap_scan(home_network)

    if scan_results:
        # Saves results to both JSON and pickle files
        print("\nSaving scan results...")

        # Save as JSON
        save_scan_results(scan_results, "json")

        # Save as pickle
        save_scan_results(scan_results, "pickle")

        # Check if we have a previous scan to compare with
        previous_scan = find_previous_xml_scan()

        if previous_scan:
            print(f"Found previous scan: {previous_scan}")

            # Run ndiff to compare scans
            diff_results = run_ndiff(previous_scan, scan_results["xml_file"])

            if diff_results:
                print("\nPort differences detected:")
                print(diff_results)

                # Save the diff results
                save_diff_results(diff_results)
            else:
                print("No differences found or ndiff failed")
        else:
            print("No previous scan found for comparison")

        print(f"Files saved in 'Logon ID' directory")

    else:
        print("Scan failed - no results to save")
        return 1

    print(" ")
    return 0

if __name__ == "__main__":
    sys.exit(main())
