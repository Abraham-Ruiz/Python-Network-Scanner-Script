#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PyNmap Network Scanner Script
"""

__author__ = "Abraham Ruiz"
__email__ = "aruiz7@students.columbiabasin.edu"  
__date__ = "May 28 2025" 
__version__ = "1.0.0"

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
    else:
        return f"{date_str}.json"

def run_nmap_scan(network="192.168.1.0/24"):
    
    print(f"Starting Nmap scan on network: {network}")
    
    # Nmap command with JSON output
    nmap_cmd = [
        "nmap", 
        "-sn",  # Ping scan
        network
    ]
    
    try:
        # Runs Nmap command
        result = subprocess.run(nmap_cmd, 
                              capture_output=True, 
                              text=True, 
                              timeout=300)  # 5 minute timeout
        
        if result.returncode == 0:
            print("Nmap scan completed successfully")
            return result.stdout
        else:
            print(f"Nmap scan failed with return code: {result.returncode}")
            print(f"Error: {result.stderr}")
            return None
            
    except subprocess.TimeoutExpired:
        print("Nmap scan timed out")
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
                "scan_type": "Network Discovery",
                "raw_output": scan_data,
                "file_format": "json"
            }
            
            with open(filepath, 'w') as f:
                json.dump(scan_info, f, indent=2)
            print(f"JSON file saved here: {filepath}")
        
        return True
        
    except Exception as e:
        print(f"Error saving file {filepath}: {e}")
        return False

def main():

    print("PyNmap Network Scanner")
    print("*" * 40)
    
    #Create Logon ID directory if needed
    if not create_logon_id_directory():
        print("Failed to create/access Logon ID directory")
        return 1
    
    # Get network to scan
    home_network = "192.168.1.137/24"
    
    print(f"Target network: {home_network}")
    
    #Runs Nmap scan
    scan_results = run_nmap_scan(home_network)
    
    if scan_results:
        # Saves results to both JSON and pickle files
        print("\nSaving scan results...")
        
        # Save as JSON
        save_scan_results(scan_results, "json")
        
        # Save as pickle
        save_scan_results(scan_results, "pickle")
        
        print(f"Files saved in 'Logon ID' directory with format: {get_filename_with_date('json')}")
        
    else:
        print("Scan failed - no results to save")
        return 1
    
    print(" ")
    return 0

if __name__ == "__main__":
    sys.exit(main())
