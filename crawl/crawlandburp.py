#/usr/bin/python3
# This script is currently developed to not use burp's REST API key.
# Could have been written much better, yet it is in "ghetto_scripts" for a reason..

#!/usr/bin/python3
import asyncio
import requests
import os
import csv
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

def read_domains_from_file_and_prepare_variants(file_path):
    domains = []
    with open(file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            domain = row[0].strip()
            if not domain.startswith('http://') and not domain.startswith('https://'):
                http_version = 'http://' + domain
                https_version = 'https://' + domain
                domains.extend([http_version, https_version])
            else:
                domains.append(domain)
    return domains

def start_burp_scan(urls, burp_api_url, scan_configuration_ids=[]):
    headers = {'Content-Type': 'application/json'}
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
        print(f"Failed to start scan task: {response.status_code} - {response.text}")
        return None

def get_scan_progress(burp_api_url, task_id):
    response = requests.get(burp_api_url + f"/v0.1/scan/{task_id}")
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to get scan progress: {response.status_code} - {response.text}")
        return None

async def monitor_scan_progress(scan_task_id, burp_api_url):
    print(f"{Colors.BOLD}Monitoring scan task ID: {scan_task_id}{Colors.ENDC}")
    bar = Bar('Progress', max=100)
    while True:
        progress_info = get_scan_progress(burp_api_url, scan_task_id)
        if progress_info:
            display_progress_info(progress_info, bar)
            scan_status = progress_info.get('scan_status')
            if scan_status in ["succeeded", "failed"]:
                bar.finish()
                print(f"Scan {scan_status}.")
                break
        await asyncio.sleep(5)

def segment_into_batches(urls, batch_size):
    for i in range(0, len(urls), batch_size):
        yield urls[i:i + batch_size]

async def process_batch(batch, burp_api_url, scan_configuration_ids):
    print(f"{Colors.BOLD}Starting scan for batch with {len(batch)} URLs.{Colors.ENDC}")
    scan_task_id = start_burp_scan(batch, burp_api_url, scan_configuration_ids)
    if scan_task_id:
        await monitor_scan_progress(scan_task_id, burp_api_url)
    else:
        print(f"{Colors.FAIL}Failed to start scan for the current batch.{Colors.ENDC}")

async def main():
    file_path = 'domains.txt'
    burp_api_url = 'http://localhost:1337'
    scan_configuration_ids = ['OptimisedCrawl', 'OptimisedAudit']

    urls = read_domains_from_file_and_prepare_variants(file_path)
    batches = segment_into_batches(urls, 250)

    for batch in batches:
        await process_batch(batch, burp_api_url, scan_configuration_ids)
        # Optional: Pause between batches if needed

if __name__ == "__main__":
    asyncio.run(main())


