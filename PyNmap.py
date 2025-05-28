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
import subprocess
import datetime
import sys

def create_logon_id_directory():
    logon_dir = "Logon ID"
    if not os.path.exists(logon_dir):
        os.makedirs(logon_dir)
        print(f"Created directory: {logon_dir}")
    else:
        print(f"Directory {logon_dir} already exists")
    return True

def get_xml_filename():
    today = datetime.datetime.now()
    date_str = today.strftime("%m%d%y")  # mmddyy format
    return f"{date_str}.xml"

def run_nmap_scan(network="192.168.1.0/24"):
    print(f"Starting Nmap scan on network: {network}")

    # XML output file
    xml_output = os.path.join("Logon ID", get_xml_filename())

    # Nmap command for TCP port scanning with XML output
    nmap_cmd = [
        "nmap",
        "-sT",       # TCP connect scan
        "-p 1-1000", # Scan common ports
        "--open",    # Only show open ports
        "-oX", xml_output,  # XML output
        network
    ]

    result = subprocess.run(nmap_cmd, capture_output=True, text=True)

    if result.returncode == 0:
        print("Nmap scan completed successfully")
        print(f"XML results saved to: {xml_output}")
        return xml_output
    else:
        print(f"Nmap scan failed: {result.stderr}")
        return None

def find_previous_xml_scan():
    logon_dir = "Logon ID"
    xml_files = [f for f in os.listdir(logon_dir) if f.endswith('.xml')]

    # Sorts files by modification time (oldest first)
    xml_files.sort(key=lambda f: os.path.getmtime(os.path.join(logon_dir, f)))

    # Returns the previous file if there are at least 2 files
    if len(xml_files) >= 2:
        return os.path.join(logon_dir, xml_files[-2])  # Second newest file

    return None

def run_ndiff(previous_xml, current_xml):
    print(f"Running ndiff to compare with previous scan...")

    ndiff_cmd = ["ndiff", previous_xml, current_xml]

    result = subprocess.run(ndiff_cmd, capture_output=True, text=True)

    if result.returncode == 0:
        return result.stdout
    else:
        print(f"ndiff failed: {result.stderr}")
        return None

def save_diff_results(diff_data):
    if not diff_data:
        print("No diff data to save")
        return

    # Creates filename for diff results
    today = datetime.datetime.now()
    date_str = today.strftime("%m%d%y")
    filename = f"diff_{date_str}.txt"
    filepath = os.path.join("Logon ID", filename)

    with open(filepath, 'w') as f:
        f.write(diff_data)
    print(f"Diff results saved to: {filepath}")

def main():
    print("PyNmap Network Scanner with ndiff")
    print("*" * 40)

    # Create Logon ID directory if needed
    create_logon_id_directory()

    # Get network to scan
    home_network = "192.168.1.137/24"
    print(f"Target network: {home_network}")

    # Run Nmap scan
    current_xml = run_nmap_scan(home_network)

    if current_xml:
        # Checks if we have a previous scan to compare with
        previous_xml = find_previous_xml_scan()

        if previous_xml:
            print(f"Found previous scan: {previous_xml}")

            # Run ndiff to compare scans
            diff_results = run_ndiff(previous_xml, current_xml)

            if diff_results:
                print("\nPort differences detected:")
                print(diff_results)

                # Save the diff results
                save_diff_results(diff_results)
            else:
                print("No differences found or ndiff failed")
        else:
            print("No previous scan found for comparison")
    else:
        print("Scan failed - no results to save")
        return 1

    print(" ")
    return 0

if __name__ == "__main__":
    sys.exit(main())
