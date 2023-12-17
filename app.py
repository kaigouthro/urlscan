import streamlit as st
from urllib.parse import parse_qs, urlparse
import nltk
import requests
import streamlit as st
from bs4 import BeautifulSoup
import socket
import json
import shutil
import os

TOP = st.container()
MAINAREA = st.columns(2)
LEFT = MAINAREA[0]
RIGHT = MAINAREA[1]
inputs = LEFT.empty()
listview = RIGHT.empty()

class PortScanner:
    def __init__(self, target_ip, port_range):
        self.target_ip = target_ip
        self.port_range = port_range

    def scan(self):
        open_ports = []
        for port in self.port_range:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports


class DirectoryScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.directories = []

    def scan(self, url, directoriees, sites=None):
        urls = sites or [url]
        full_urls = set()
        for url in urls:
            if url.startswith(r"http.?:\/\/"):
                url = url.split("//")[1]
            target_url = url or self.target_url
            p = TOP.progress(0.0)
            sz = len(directoriees)

            for w, word in enumerate(directoriees):
                full_url = f"{target_url}/{word}"
                p.progress((w + 1) / sz * 100, f"Scanning {full_url}")
                try:
                    response = requests.get(f"https://{full_url}", timeout=5)
                    if response.status_code == 200:
                        full_urls.add(full_url)
                        RIGHT.write(f"https://{full_url}")
                except:
                    pass
            p.empty()
        return list(full_urls)

    @staticmethod
    def extract_directories(response_text):
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
        self.subdomains = {"www": {"ports": []}}

    def scan_ports(self, ip):
        port_scanner = PortScanner(ip, range(1, 100))
        open_ports = port_scanner.scan()
        for port in open_ports:
            print(f"Open port found: {port}")

    def scan(self, url, wordlist):
        if url.startswith(r"http.?:\/\/"):
            url = url.split("//")[1]
        target_url = url or self.target_url
        subdomains = set()
        p = TOP.progress(0.0)
        sz = len(wordlist)

        for w, word in enumerate(wordlist):
            subdomain = f"{word}.{target_url}"
            p.progress((w + 1) / sz * 100, f"Scanning {subdomain}")
            if len(subdomains) == 0:
                try:
                    response = requests.get(f"https://zzzzzzzzzzzzzzzzzzzzzzzzzz{subdomain}", timeout=0.1)
                    TOP.error("Wildcards Forwarding to main..")
                    if response:
                        st.stop()
                except:
                    subdomains.add("www")
                    continue
            try:
                response = requests.get(f"https://{subdomain}", timeout=1)
                if response.status_code == 200:
                    subdomains.add(subdomain)
                    RIGHT.write(f"https://{subdomain}")
            except:
                pass
        p.empty()
        return subdomains


class UrlParameterScanner:
    def __init__(self, url, keys=None, **kwargs):
        self.target_url = url
        self.parameters = {"keys": keys or [], **kwargs}

    def scan(self, url=None, parameters=None, sites=None):
        urls = sites or [url]
        for url in urls:
            if url.startswith(r"http.?:\/\/"):
                url = url.split("//")[1]
            parsed_url = urlparse(url or self.target_url)
            base_url = parsed_url.scheme + "://" + parsed_url.netloc
            query_string = parsed_url.query
            matches = {}

            if query_string:
                params = parameters or parse_qs(query_string)
                for parameter, values in params.items():
                    self.parameters[parameter] = values

            dispfound = TOP.empty()
            disp = RIGHT.empty()
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


def filter_wordlist(wordlist, threshold):
    filtered_wordlist = []
    wordlist = wordlist.split("\n")

    for word in wordlist:
        likelihood = calculate_likelihood(word, wordlist)
        if likelihood >= threshold:
            filtered_wordlist.append(word)

    return filtered_wordlist


def calculate_likelihood(word, wordlist):
    total_words = len(wordlist)
    word_count = wordlist.count(word)
    likelihood = word_count / total_words
    likelihood = min(max(likelihood, 0), 1)
    nltk_likelihood = nltk.edit_distance(word, word) / len(word)
    nltk_likelihood = 1 - nltk_likelihood
    nltk_likelihood = min(max(nltk_likelihood, 0), 1)

PARAMETER_LIST = {
    "keys" : "https://raw.githubusercontent.com/danielmiessler/SecLists/b19db4023a35d6180646cc3641718429addbfa64/Discovery/Web-Content/api/objects.txt",
    "values" : "https://raw.githubusercontent.com/danielmiessler/SecLists/b19db4023a35d6180646cc3641718429addbfa64/Passwords/cirt-default-passwords.txt"
    }

def main():
    TOP.title("Web Scanner")
    scanner_type = st.sidebar.selectbox(
        "Select Scanner:",
        ["Subdomain Scanner", "Directory Scanner", "URL Parameter Scanner"],
        index=0,
    )
    word_list = st.sidebar.selectbox("Enter Word List:", WORD_LIST_URLS)
    target_url = LEFT.text_input("Enter Target URL:")
    json_file_path = st.session_state.get("json_file_path", "results.json")
    parameters = create_dictionaries(PARAMETER_LIST)
    st.session_state["json_file_path"] = json_file_path

    if scanner_type and LEFT.button(scanner_type, key="scantype"):
        scanner = scanners[scanner_type](target_url)
        RIGHT.text(f"{scanner_type.split(' Scanner')[0]} {target_url}")

        if target_url in st.session_state["found_addresses"]["sites"]:
            st.session_state["found_addresses"]["sites"][target_url] = {"subdomains": {}}

        if isinstance(scanner, SubdomainScanner):
            output = scanner.scan(target_url, word_list)
            st.session_state["found_addresses"]["sites"][target_url]["subdomains"] = output

        if isinstance(scanner, DirectoryScanner):
            output = scanner.scan(target_url, word_list)
            st.session_state["found_addresses"]["sites"][target_url]["directoriees"] = output

        if isinstance(scanner, UrlParameterScanner):

            parameter_names = st.sidebar.multiselect("Enter Parameter Names:", list(parameters.keys()))
            parameter_values = st.sidebar.multiselect("Enter Parameter Values:", list(parameters.values()))
            filtered_parameters = {k: v for k, v in parameters.items() if k in parameter_names}
            filtered_values = set(parameter for k, v in filtered_parameters.items() for parameter in v if parameter in parameter_values)
            output = scanner.scan(target_url, parameters=filtered_parameters, sites=filtered_values)
            st.session_state["found_addresses"]["sites"][target_url]["parameters"] = output

        with open(json_file_path, "w") as json_file:
            json.dump(st.session_state["found_addresses"], json_file)

        LEFT.write(st.session_state["found_addresses"])

if __name__ == "__main__":
    WORD_LIST_URLS = [
        "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_tiny.txt",
        "https://raw.githubusercontent.com/xajkep/wordlists/master/discovery/directory_only_one.small.txt",
        "https://raw.githubusercontent.com/Damian89/xssfinder/master/wordlists/params.txt",
    ]


    scanners = {
        "Subdomain Scanner": SubdomainScanner,
        "Directory Scanner": DirectoryScanner,
        "URL Parameter Scanner": UrlParameterScanner
    }

    main()
