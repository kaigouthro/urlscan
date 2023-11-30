import streamlit as st
from urllib.parse import parse_qs, urlparse
import nltk
import requests
import streamlit as st
from bs4 import BeautifulSoup


class DirectoryScanner:
    """
    A class for scanning directories from a target URL.

    Attributes:
    target_url (str): The target URL to scan directories from.
    directories (list): A list of directory URLs found during scanning.
    """

    def __init__(self, target_url):
        """
        Initialize a DirectoryScanner object.
        Args:
        target_url (str): The target URL to scan directories from.
        """
        self.target_url = target_url
        self.directories = []

    def scan(self, url, directoriees, sites = None):
        """
        Scan directories from the target URL.

        This method sends a HTTP GET request to the target URL and extracts
        directory URLs found in the response.
        """
        urls = sites or  [url]
        for url in urls:
            if url.startswith(r"http.?:\/\/"):
                url = url.split("//")[1]
            target_url = url or self.target_url
            subdomains = set()
            p = st.progress(0.0)
            sz = len(directoriees)
    
            for w, word in enumerate(directoriees):
                subdomain = f"{target_url}/{word}"
                p.progress(w / sz, f"Scanning {subdomain}")
                try:
                    response = requests.get(f"https://{subdomain}", timeout=5)
                    if response.status_code == 200:
                        subdomains.add(subdomain)
                        st.write(f"https://{subdomain}")
                except:
                    pass
            p.empty()
        return subdomains

    @staticmethod
    def extract_directories(response_text):
        """
        Extract directory URLs from the given response text.

        Args:
        response_text (str): The HTML response text.

        Returns:
        list: A list of directory URLs found in the response text.
        """
        directories = []
        soup = BeautifulSoup(response_text, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href.endswith("/"):
                directories.append(href)
        return directories

class SubdomainScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        
    def scan(self, url, wordlist):
        if url.startswith(r"http.?:\/\/"):
            url = url.split("//")[1]
        target_url = url or self.target_url
        subdomains = set()
        p = st.progress(0.0)
        sz = len(wordlist)

        for w, word in enumerate(wordlist):
            subdomain = f"{word}.{target_url}"
            p.progress(w / sz, f"Scanning {subdomain}")
            if len(subdomains) ==0 :
                try:
                    response = requests.get(f"https://zzzzzzzzzzzzzzzzzzzzzzzzzz{subdomain}", timeout=0.1)
                    st.error("Wildcards Forwarding to main..")
                    st.stop()
                except:
                    subdomains.add("www")
                    continue
            try:

                response = requests.get(f"https://{subdomain}", timeout=1)
                if response.status_code == 200:
                    subdomains.add(subdomain)
                    st.write(f"https://{subdomain}")
            except:
                pass
        p.empty()
        return subdomains

class UrlParameterScanner:
    def __init__(self, url, keys = None, **kwargs):
        self.target_url = url
        self.parameters = {"keys": keys or [], **kwargs}

    def scan(self,url = None, parameters = None, sites = None):
        urls = sites or  [url]
        for url in urls:
            if url.startswith(r"http.?:\/\/"):
                url = url.split("//")[1]           
            parsed_url = urlparse(url or self.target_url)
            base_url = parsed_url.scheme + "://" + parsed_url.netloc
            query_string = parsed_url.query
            matches = {} # key : [values]
            if query_string:
                params =parameters or  parse_qs(query_string)
                for parameter, values in params.items():
                    self.parameters[parameter] = values
            dispfound = st.empty()
            disp      = st.empty()
            for parameter, values in self.parameters.items():
                for value in values:
                    url = base_url + "?" + parameter + "=" + value
                    response = requests.get(url)
                    
                    if response.status_code == 200:
                        matches[parameter].append(value)
                        dispfound.write("Potential vulnerability found:", parameter, value)
                    else:
                        disp.write("Not vulnerable:", url)
    
    def get_parameters(self):
        return self.parameters


def create_dictionaries(word_list_urls):
    dictionaries = {}
    for url in word_list_urls:
        word_list = load_word_list(url)
        dictionary_name = get_dictionary_name(url)
        dictionaries[dictionary_name] = word_list
    return dictionaries

def load_word_list(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.split("\n")
    raise Exception(f"Failed to load word list from {url}")

def get_dictionary_name(url):
    return url.split("/")[-1].split(".")[0]


WORD_LIST_URLS = [
    "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_tiny.txt",
    "https://raw.githubusercontent.com/xajkep/wordlists/master/discovery/directory_only_one.small.txt",
    "https://raw.githubusercontent.com/Damian89/xssfinder/master/wordlists/params.txt",
]


# Load the word lists and create dictionaries
DICTIONARIES = create_dictionaries(WORD_LIST_URLS)

    # Normalize the likelihood to a value between 0 and 1
def calculate_likelihood(word, wordlist):
    total_words = len(wordlist)
    word_count = wordlist.count(word)

    # Calculate the likelihood of the word based on its count in the wordlist
    likelihood = word_count / total_words

    # Normalize the likelihood to a value between 0 and 1
    likelihood = min(max(likelihood, 0), 1)

    # use nltk to calculate the likelihood of the word
    nltk_likelihood = nltk.edit_distance(word, word) / len(word)
    nltk_likelihood = 1 - nltk_likelihood

    # Normalize the likelihood to a value between 0 and 1
    nltk_likelihood = min(max(nltk_likelihood, 0), 1)


def filter_wordlist(wordlist, threshold):
    filtered_wordlist = []
    wordlist = wordlist.split("\n")
    # Calculate likelihood for each word in the wordlist
    for word in wordlist:
        likelihood = calculate_likelihood(word, wordlist)

        # Filter out unlikely words based on the threshold
        if likelihood >= threshold:
            filtered_wordlist.append(word)

    return filtered_wordlist


# Create the Streamlit app
def main():
    st.title("Web Scanner")

    # Options for selecting the scanner type
    scanner_type = st.sidebar.selectbox(
        "Select Scanner:", [
            "Directory Scanner",
            "URL Parameter Scanner",
            "Subdomain Scanner"
            ],  0)

    word_list = DICTIONARIES[st.sidebar.selectbox("Enter Word List:", list(DICTIONARIES.keys()))]
    target_url = st.text_input("Enter Target URL:")
    found_addresses = {"sites": { "example.com" :{ "subdomains":
        { "www" : { "directoriees":[]}}}}}

    st.session_state['found_addresses'] = st.session_state.get ("found_addresses", found_addresses)
    disparea = st.empty()
    scanners = {
        "Directory Scanner": DirectoryScanner,
        "Subdomain Scanner": SubdomainScanner,
        "URL Parameter Scanner": UrlParameterScanner
    }

    if scanner_type and st.button(scanner_type, key="scantype"):
        scanner = scanners[scanner_type](target_url)
        st.text(scanner_type.replace(" Scanner", ":"))
        # change thhe classes above before writing
        output = scanner.scan(target_url, word_list)
        if target_url in st.session_state['found_addresses']["sites"]:
            st.session_state['found_addresses']["sites"][target_url] = {"subdomains": {}}
        if isinstance(scanner , SubdomainScanner):
            st.session_state['found_addresses']["sites"][target_url]["subdomains"] = output
        if isinstance(scanner , DirectoryScanner):
            st.session_state['found_addresses']["sites"][target_url]["directoriees"] = output
        if isinstance(scanner , UrlParameterScanner):
            st.session_state['found_addresses']["sites"][target_url]["parameters"] = output
        disparea.write(st.session_state['found_addresses'])

                # scan for subdomains, then eachh subdomain for subdirectories, and scan each subdirectory for parameters

        st.session_state.sync()

# Run the app
if __name__ == "__main__":
    main()
