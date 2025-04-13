import requests
from bs4 import BeautifulSoup
from tldextract import extract
import whois

def extract_features(url):
    features = []
    
    # Extract URL length
    features.append(len(url))
    
    # Extract domain-related features
    domain_info = extract(url)
    features.append(domain_info.domain)
    
    try:
        w = whois.whois(url)
        features.append(w.creation_date is not None)  # domain age info
    except:
        features.append(False)
    
    # Extract HTML content features (example: presence of form tag)
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        features.append(len(soup.find_all('form')))  # number of forms in the page
    except requests.exceptions.RequestException:
        features.append(0)
    
    return features
