# PyNmap Network Scanner

This repository contains the three itterations the network scanning tool went through for CSIA310:

- **PyNmap_v1.py**: Imports: os, json, pickle, subprocess, datetime, sys.
                    create_logon_id_directory(): Creates "Logon ID" directory with error handling.
                    get_filename_with_date(): Generates filenames for JSON or Pickle.
                    run_nmap_scan(): Runs nmap -sn, returns stdout, has timeout and error handling.
                    save_scan_results(): Saves data to JSON (with timestamp, scan_type) or Pickle, with error handling.
                    main(): Directs directory creation, scan, and saving to both JSON and Pickle.
  
- **PyNmap_v1.2.py**: Same thing as the previous script, except it now outputs the data in XML format

