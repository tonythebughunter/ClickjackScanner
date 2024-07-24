# PREREQUISITE
python && pip
# INSTALLATION

git clone https://github.com/tonythebughunter/ClickjackScanner && cd ClickjackScanner && pip install -r requirements.txt

# USAGE 

python clickjacker.py <urls_file> [OPTIONS]

# OPTIONS
-v or --verbose: Enables verbose output.

-w or --workers: Specifies the number of concurrent workers.

-o or --output: Specifies the output file for vulnerable URLs. Default is vulnerable_urls.txt.

# EXAMPLE

python clickjacker.py all_urls.txt -w 40 -v -o clickjack_vulnerable.txt

# VERBOSE OUTPUT
Green : vulnerable URLs

Red : non-vulnerable or inaccessible URLs.
