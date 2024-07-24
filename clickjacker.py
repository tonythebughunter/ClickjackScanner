import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import os
from colorama import Fore, Style, init

init(autoreset=True)

def check_clickjacking(url, verbose=False):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            if 'X-Frame-Options' in response.headers:
                result = f'{url}: not vulnerable (protected with X-Frame-Options: {response.headers["X-Frame-Options"]})'
                color = Fore.RED
            elif 'Content-Security-Policy' in response.headers:
                csp = response.headers['Content-Security-Policy']
                if 'frame-ancestors' in csp:
                    result = f'{url}: not vulnerable (protected with Content-Security-Policy: frame-ancestors {csp})'
                    color = Fore.RED
                else:
                    result = f'{url}: not vulnerable (no frame-ancestors in Content-Security-Policy)'
                    color = Fore.RED
            else:
                result = f'{url}: vulnerable (no X-Frame-Options or CSP frame-ancestors)'
                color = Fore.GREEN
        else:
            result = f'{url}: not accessible (status code: {response.status_code})'
            color = Fore.RED
    except requests.exceptions.RequestException as e:
        result = f'{url}: not accessible (error: {str(e)})'
        color = Fore.RED

    if verbose:
        print(color + result)
    return result

def main(urls_file, max_workers, output_file, verbose):
    with open(urls_file, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    vulnerable_urls = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_clickjacking, url, verbose): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if "vulnerable" in result:
                    vulnerable_urls.append(url)
            except Exception as exc:
                if verbose:
                    print(Fore.RED + f'{url}: generated an exception: {exc}')

    # Write the vulnerable URLs to the specified output file
    with open(output_file, 'w') as vulnerable_file:
        for url in vulnerable_urls:
            vulnerable_file.write(url + '\n')

    print(f"Vulnerable URLs have been saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check for clickjacking vulnerabilities.')
    parser.add_argument('urls_file', help='Path to the file containing URLs to check.')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-o', '--output', default='vulnerable_urls.txt', help='Output file for vulnerable URLs (default: vulnerable_urls.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()
    main(args.urls_file, args.workers, args.output, args.verbose)
