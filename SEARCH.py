import requests
import json
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def search_github_repositories(query):
    url = f"https://api.github.com/search/repositories?q={query}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if 'items' in data:
            print(f"{Fore.YELLOW}Found {len(data['items'])} repositories for query '{query}':{Style.RESET_ALL}\n")
            for item in data['items']:
                name = item['name']
                html_url = item['html_url']
                print(f"{Fore.CYAN}{name}: {Fore.GREEN}{html_url}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}No repositories found for query '{query}'{Style.RESET_ALL}")
    
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    query = input("Enter search query: ")
    search_github_repositories(query)
