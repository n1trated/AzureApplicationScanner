#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import json
import re
import sys
import time
import csv
import os
from concurrent.futures import ThreadPoolExecutor

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Detect applications in Azure tenant')
    parser.add_argument('-t', '--tenant', required=True, help='Target Azure tenant domain')
    parser.add_argument('-f', '--file', required=True, help='File path containing client_id list (supports TXT or CSV formats)')
    parser.add_argument('-o', '--output', help='Result output file path')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('-d', '--delay', type=float, default=0.5, help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Output detailed information')
    return parser.parse_args()

def check_app_existence(client_id, tenant, display_name="", verbose=False):
    """Check if an application exists in the specified tenant"""
    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
    
    # Intentionally use an invalid client_secret
    data = {
        'client_id': client_id,
        'client_secret': 'invalid_secret',
        'scope': 'https://graph.microsoft.com/.default',
        'grant_type': 'client_credentials'
    }
    
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    try:
        response = requests.post(url, data=data, headers=headers)
        error_json = response.json()
        
        error_code = error_json.get('error_codes', [0])[0]
        error_description = error_json.get('error_description', '')
        
        if verbose:
            print(f"[DEBUG] Client ID: {client_id}, Error Code: {error_code}")
        
        # Error code 7000215 indicates the application exists but the client_secret is invalid
        if error_code == 7000215:
            return {
                'client_id': client_id,
                'display_name': display_name,
                'status': 'exists',
                'error_code': error_code,
                'error_description': error_description
            }
        # Error code 700016 indicates the application does not exist
        elif error_code == 700016:
            return {
                'client_id': client_id,
                'display_name': display_name,
                'status': 'not_found',
                'error_code': error_code,
                'error_description': error_description
            }
        else:
            return {
                'client_id': client_id,
                'display_name': display_name,
                'status': 'unknown',
                'error_code': error_code,
                'error_description': error_description
            }
    except Exception as e:
        return {
            'client_id': client_id,
            'display_name': display_name,
            'status': 'error',
            'error_message': str(e)
        }

def load_client_ids_from_txt(file_path):
    """Load client_id list from a TXT file"""
    app_info = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            client_id = line.strip()
            if client_id:
                app_info.append({
                    'client_id': client_id,
                    'display_name': ''
                })
    return app_info

def load_client_ids_from_csv(file_path):
    """Load client_id list from a CSV file"""
    app_info = []
    with open(file_path, 'r', encoding='utf-8') as f:
        # Try to determine if the file is tab-delimited or comma-delimited
        first_line = f.readline().strip()
        f.seek(0)  # Reset file pointer to the beginning
        
        delimiter = '\t' if '\t' in first_line else ','
        csv_reader = csv.DictReader(f, delimiter=delimiter)
        
        for row in csv_reader:
            if 'appId' in row and row['appId'].strip():
                app_info.append({
                    'client_id': row['appId'].strip(),
                    'display_name': row.get('displayName', '').strip()
                })
    return app_info

def main():
    args = parse_arguments()
    
    # Determine how to read the client_id list based on file extension
    app_info = []
    file_extension = os.path.splitext(args.file)[1].lower()
    
    try:
        if file_extension == '.txt':
            print(f"[INFO] Detected TXT format file")
            app_info = load_client_ids_from_txt(args.file)
        elif file_extension == '.csv' or file_extension == '.tsv':
            print(f"[INFO] Detected CSV format file")
            app_info = load_client_ids_from_csv(args.file)
        else:
            # Try to guess the file type based on content
            with open(args.file, 'r', encoding='utf-8') as f:
                first_line = f.readline().strip()
                if '\t' in first_line or ',' in first_line and any(header in first_line for header in ['appId', 'displayName']):
                    print(f"[INFO] Identified as CSV format file based on content")
                    app_info = load_client_ids_from_csv(args.file)
                else:
                    print(f"[INFO] Identified as TXT format file based on content")
                    app_info = load_client_ids_from_txt(args.file)
    except Exception as e:
        print(f"Error: Unable to read file: {e}")
        sys.exit(1)
    
    if not app_info:
        print("Error: No valid application ID data found")
        sys.exit(1)
    
    print(f"[INFO] Starting detection in tenant {args.tenant}")
    print(f"[INFO] Loaded {len(app_info)} application IDs")
    
    results = []
    found_apps = []
    
    # Create thread pool for concurrent requests
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = []
        for app in app_info:
            futures.append(executor.submit(
                check_app_existence, 
                app['client_id'], 
                args.tenant, 
                app['display_name'],
                args.verbose
            ))
            time.sleep(args.delay)  # Add delay to avoid requesting too quickly
        
        # Get results
        for future in futures:
            result = future.result()
            results.append(result)
            
            if result['status'] == 'exists':
                found_apps.append(result)
                print(f"[FOUND] App Name: {result['display_name'] or 'Unknown'}, App ID: {result['client_id']}")
    
    # Output result summary
    print(f"\n[RESULT] Total applications checked: {len(app_info)}")
    print(f"[RESULT] Found existing applications: {len(found_apps)}")
    
    # Save results to file
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2)
            print(f"[INFO] Results saved to {args.output}")
        except Exception as e:
            print(f"[ERROR] Unable to save results: {e}")
    
    # Print the found applications
    if found_apps:
        print("\nExisting application list:")
        for app in found_apps:
            print(f"- Name: {app['display_name'] or 'Unknown'}, ID: {app['client_id']}")

if __name__ == "__main__":
    main() 