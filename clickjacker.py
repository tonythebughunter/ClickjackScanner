import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os

def check_clickjacking(url, verbose=False):
    if verbose:
        print(f'Starting check for: {url}')
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            if 'X-Frame-Options' in response.headers:
                result = f'{url} is protected with X-Frame-Options: {response.headers["X-Frame-Options"]}'
            elif 'Content-Security-Policy' in response.headers:
                csp = response.headers['Content-Security-Policy']
                if 'frame-ancestors' in csp:
                    result = f'{url} is protected with Content-Security-Policy: frame-ancestors {csp}'
                else:
                    result = f'{url} does not have frame-ancestors in Content-Security-Policy'
            else:
                result = f'{url} is vulnerable to clickjacking (no X-Frame-Options or CSP frame-ancestors)'
        else:
            result = f'Failed to access {url} (status code: {response.status_code})'
    except requests.exceptions.RequestException as e:
        result = f'Error accessing {url}: {str(e)}'
    
    if verbose:
        print(f'Finished check for: {url}')
    return result

def main(urls_file, max_workers, verbose):
    with open(urls_file, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    results = []
    vulnerable_urls = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_clickjacking, url, verbose): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
                if "vulnerable to clickjacking" in result:
                    vulnerable_urls.append(url)
            except Exception as exc:
                results.append(f'{url} generated an exception: {exc}')

    # Write the results to a file
    with open('clickjacking_results.txt', 'w') as result_file:
        for result in results:
            result_file.write(result + '\n')
    
    # Write the vulnerable URLs to a separate file
    with open('vulnerable_urls.txt', 'w') as vulnerable_file:
        for url in vulnerable_urls:
            vulnerable_file.write(url + '\n')

    print("All results have been saved to clickjacking_results.txt")
    print("Vulnerable URLs have been saved to vulnerable_urls.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check for clickjacking vulnerabilities.')
    parser.add_argument('urls_file', help='Path to the file containing URLs to check.')
    parser.add_argument('--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    main(args.urls_file, args.workers, args.verbose)
