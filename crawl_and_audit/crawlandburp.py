#/usr/bin/python3
# This script is currently developed to not use burp's api keys.
# However this can be added, as most support for API keys is integrated
# It is important however, that ApiKey is placed in GET request as per
# Burp's REST API documentation and so this script needs minor tweaking to do so.
# Could have been written much better, yet it is in "ghetto_scripts" for a reason..

import requests
import time
import os
from urllib.parse import urlparse
from progress.bar import Bar

# ANSI color codes for colored output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_issues(issues):
    for severity in ['high', 'medium', 'low']:
        for issue in issues:
            issue_details = issue.get('issue', {})
            if issue_details.get('severity') == severity and issue_details.get('confidence') in ['certain', 'firm']:
                print(f"{Colors.FAIL if severity == 'high' else Colors.WARNING if severity == 'medium' else Colors.OKBLUE}Issue: {issue_details.get('name')} {Colors.ENDC}")
                print(f"  Origin: {issue_details.get('origin')}")
                print(f"  Path: {issue_details.get('path')}")
                print(f"  Severity: {issue_details.get('severity')}")
                print(f"  Confidence: {issue_details.get('confidence')}\n")

def display_progress_info(info, bar):
    clear_console()
    metrics = info.get("scan_metrics", {})

    progress = metrics.get('crawl_and_audit_progress', 0)
    bar.goto(progress)
    print(Colors.OKGREEN)
    bar.finish()
    print(Colors.ENDC)

    print(Colors.OKBLUE + f"Scan Status: {info.get('scan_status')}" + Colors.ENDC)
    print(Colors.OKGREEN + "Scan Metrics:" + Colors.ENDC)
    print(f"  Crawl Requests Made: {metrics.get('crawl_requests_made', 0)}")
    print(f"  Unique Locations Visited: {metrics.get('crawl_unique_locations_visited', 0)}")
    print(f"  Audit Queue Items Completed: {metrics.get('audit_queue_items_completed', 0)}")
    print(f"  Total Elapsed Time: {metrics.get('total_elapsed_time', 0)} seconds")
    print(f"  Estimated Time Remaining: {metrics.get('crawl_and_audit_caption', 'N/A')}")

    issues = info.get('issue_events', [])
    if issues:
        print(Colors.BOLD + "Issues Found:" + Colors.ENDC)
        display_issues(issues)

def get_base_domain(url):
    parts = urlparse(url).netloc.split('.')
    return '.'.join(parts[-2:]) if len(parts) > 2 else url

def check_for_redirects(url):
    try:
        response = requests.get(url, allow_redirects=False)
        if response.status_code in [301, 302, 307, 308]:
            location = response.headers.get('Location', '')
            if location.startswith('https://'):
                return location
            elif location:
                return urlparse(url)._replace(scheme='https', path=location).geturl()
    except requests.RequestException as e:
        print(f"Error checking for redirects for {url}: {e}")
    return url

def prepare_urls_for_scanning(file_path):
    prepared_urls = []
    with open(file_path, 'r') as file:
        for line in file:
            domain = line.strip()
            if not domain.startswith(('http://', 'https://')):
                domain = 'http://' + domain
            final_url = check_for_redirects(domain)
            prepared_urls.append(final_url)
    return prepared_urls

def start_burp_scan(urls, burp_api_url, burp_api_key, scan_configuration_ids=[]):
    headers = {
        'Content-Type': 'application/json',
        'X-Portswigger-API-Key': burp_api_key
    }
    data = {
        "urls": urls,
        "scan_configurations": [{"type": "NamedConfiguration", "name": config_id} for config_id in scan_configuration_ids]
    }
    response = requests.post(burp_api_url + "/v0.1/scan", headers=headers, json=data)
    if response.status_code == 201:
        location_header = response.headers.get('Location')
        if location_header:
            task_id = location_header.split('/')[-1]
            return task_id
        else:
            return None
    else:
        return None

def get_scan_progress(burp_api_url, burp_api_key, task_id):
    headers = {
        'X-Portswigger-API-Key': burp_api_key
    }
    response = requests.get(burp_api_url + f"/v0.1/scan/{task_id}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def monitor_scan_progress(scan_task_id, burp_api_url, burp_api_key):
    print(f"Monitoring scan task ID: {scan_task_id}")
    bar = Bar('Progress', max=100)

    while True:
        progress_info = get_scan_progress(burp_api_url, burp_api_key, scan_task_id)
        if progress_info:
            display_progress_info(progress_info, bar)
            scan_status = progress_info.get('scan_status')
            if scan_status in ["succeeded", "failed"]:
                bar.finish()
                print(f"Scan {scan_status}.")
                break
        time.sleep(5)

def read_domains_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

# Script setup and execution
file_path = 'domains.txt'
burp_api_url = 'http://localhost:1337'
burp_api_key = 'your_api_key_here'
scan_configuration_ids = ['OptimisedCrawl', 'OptimisedAudit']

urls_for_scanning = prepare_urls_for_scanning(file_path)
scan_task_id = start_burp_scan(urls_for_scanning, burp_api_url, burp_api_key, scan_configuration_ids)

if scan_task_id:
    monitor_scan_progress(scan_task_id, burp_api_url, burp_api_key)
