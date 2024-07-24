# PREREQUISITE
python && pip
# INSTALLATION

git clone https://github.com/tonythebughunter/ClickjackScanner && cd ClickjackScanner && pip install -r requirements.txt

# USAGE 

python clickjacker.py <urls_file> [OPTIONS]

# OPTIONS
-h, --help            show this help message and exit

-w WORKERS, --workers WORKERS
                        Number of concurrent workers (default: 10)
                        
-o OUTPUT, --output OUTPUT
                        Output file for vulnerable URLs (default: vulnerable_urls.txt)
                        
-v, --verbose         Enable verbose output

# EXAMPLE

python clickjacker.py all_urls.txt -w 40 -v -o clickjack_vulnerable.txt

# VERBOSE OUTPUT
Green : vulnerable URLs

Red : non-vulnerable or inaccessible URLs.
