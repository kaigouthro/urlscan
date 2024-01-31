import streamlit as st
from urllib.parse import parse_qs, urlparse
import nltk
from typing import Dict, List, Optional, Any, Tuple, Union
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
    def __init__(self, target_ip: str, port_range: range):
        self.target_ip = target_ip
        self.port_range = port_range

    def scan(self) -> List[int]:
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
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.directories = []

    def scan(self, _url : str, directories: List[str], sites: Optional[List[str]] = None) -> List[str]:
        urls : List[str] = sites or [_url]
        full_urls = set()
        for url in urls:
            if url.startswith(r"http.?:\/\/"):
                url = url.split("//")[1]
            target_url = url or self.target_url
            progress_bar = TOP.progress(0.0)
            size = len(directories)

            for i, directory in enumerate(directories):
                full_url = f"{target_url}/{directory}"
                progress_bar.progress((i + 1) / size * 100, f"Scanning {full_url}")
                try:
                    response = requests.get(f"https://{full_url}", timeout=5)
                    if response.status_code == 200:
                        full_urls.add(full_url)
                        RIGHT.write(f"https://{full_url}")
                except:
                    pass
            progress_bar.empty()
        return list(full_urls)

    @staticmethod
    def extract_directories(response_text: str) -> List[str]:
        directories = []
        soup = BeautifulSoup(response_text, "html.parser")
        for link in soup.find_all("a"):
            href = link.get("href")
            if href.endswith("/"):
                directories.append(href)
        return directories


class SubdomainScanner:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.subdomains = {"www": {"ports": []}}

    def scan_ports(self, ip: str) -> List[int]:
        port_scanner = PortScanner(ip, range(1, 100))
        open_ports = port_scanner.scan()
        return open_ports

    def scan(self, _url : str, wordlist: List[str]) -> Dict[str, Any]:
        if _url.startswith(r"http.?:\/\/"):
            _url = _url.split("//")[1]
        target_url = _url or self.target_url
        subdomains = set()
        progress_bar = TOP.progress(0.0)
        size = len(wordlist)
        self.subdomains = {}

        for i, word in enumerate(wordlist):
            subdomain = f"{word}.{target_url}"
            progress_bar.progress((i / (1 + size)), f"Scanning {subdomain}")
            if i <= 2:
                try:
                    requests.get(f"https://abcdefg12341234123412341234.{target_url}", timeout=5)
                    st.error(f"Error: {target_url} is likely accepting all subdomains.")
                    st.stop()
                except:
                    continue
            try:
                socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((subdomain, 443))
                # response = requests.get(f"https://{subdomain}", timeout=5)
                # if response.status_code == 200:
                subdomains.add(subdomain)
                RIGHT.write(f"https://{subdomain}")
                subdomains.add(subdomain)
            except:
                try:
                    ports = self.scan_ports(subdomain)
                    self.subdomains[subdomain] = {"ports": ports}
                except:
                    continue
        progress_bar.empty()
        self.subdomains["found"] = list(subdomains)
        return self.subdomains


class UrlParameterScanner:
    def __init__(self, url: str, keys: Optional[List[str]] = None, **kwargs: Union[str, List[str]]):
        self.target_url = url
        self.parameters = {"keys": keys or [], **kwargs}

    def scan(self, url: Optional[str] = None, parameters: Optional[Dict[str, List[str]]] = None, sites: Optional[List[str]] = None) -> List[Dict[str, List[str]]]:
        urls = sites or [url]
        matched = []
        for url in urls:
            if url and url.startswith(r"http.?:\/\/"):
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
                    if url is not None:
                        response = requests.get(str(url))

                        if response.status_code == 200:
                            matches[parameter].append(value)
                            dispfound.write("Potential vulnerability found:", parameter, value)
                        else:
                            disp.write("Not vulnerable:", url)
        return matched

    def get_parameters(self) -> Dict[str, List[str]]:
        return self.parameters


def create_dictionaries(word_list_urls: Union[List[str], Dict[str, str]]) -> Dict[str, List[str]]:
    dictionaries = {}
    if isinstance(word_list_urls, list):
        for url in word_list_urls:
            word_list = load_word_list(url)
            dictionary_name = get_dictionary_name(url)
            dictionaries[dictionary_name] = word_list
    elif isinstance(word_list_urls, dict):
        for dictionary_name, url in word_list_urls.items():
            word_list = load_word_list(url)
            dictionaries[dictionary_name] = word_list
    return dictionaries


def load_word_list(url: str) -> List[str]:
    response = requests.get(url)
    if response.status_code == 200:
        return response.text.split("\n")
    raise Exception(f"Failed to load word list from {url}")


def get_dictionary_name(url: str) -> str:
    return url.split("/")[-1].split(".")[0]


def filter_wordlist(_wordlist: str, threshold: float) -> List[str]:
    filtered_wordlist = []
    wordlist = _wordlist.split("\n")

    for word in wordlist:
        likelihood = calculate_likelihood(word, wordlist)
        if likelihood >= threshold:
            filtered_wordlist.append(word)

    return filtered_wordlist


def calculate_likelihood(word: str, wordlist: List[str]) -> float:
    total_words = len(wordlist)
    word_count = wordlist.count(word)
    likelihood = word_count / total_words
    likelihood = min(max(likelihood, 0), 1)
    nltk_likelihood = nltk.edit_distance(word, word) / len(word)
    nltk_likelihood = 1 - nltk_likelihood
    nltk_likelihood = min(max(nltk_likelihood, 0), 1)
    return (likelihood + nltk_likelihood) / 2


PARAMETER_LIST = {
    "objects": "https://raw.githubusercontent.com/danielmiessler/SecLists/b19db4023a35d6180646cc3641718429addbfa64/Discovery/Web-Content/api/objects.txt",
    "passwords": "https://raw.githubusercontent.com/danielmiessler/SecLists/b19db4023a35d6180646cc3641718429addbfa64/Passwords/cirt-default-passwords.txt",
}

scanners = {
    "Subdomain Scanner": SubdomainScanner,
    "Directory Scanner": DirectoryScanner,
    "URL Parameter Scanner": UrlParameterScanner,
}
WORD_LIST_URLS = [
    "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_tiny.txt",
    "https://raw.githubusercontent.com/xajkep/wordlists/master/discovery/directory_only_one.small.txt",
    "https://raw.githubusercontent.com/Damian89/xssfinder/master/wordlists/params.txt",
]


def main():
    TOP.title("Web Scanner")
    scanner_type = st.sidebar.selectbox("Select Scanner:", ["Subdomain Scanner", "Directory Scanner", "URL Parameter Scanner"], index=0)
    WORDLISTS : Dict[str, List[str]] = create_dictionaries(WORD_LIST_URLS)
    st.sidebar.markdown("## Word Lists")
    word_list = st.sidebar.selectbox("Enter Word List:", WORDLISTS) or "objects"
    target_url = LEFT.text_input("Enter Target URL:")
    json_file_path = st.session_state.get("json_file_path", "results.json")
    parameters = create_dictionaries(PARAMETER_LIST)
    st.session_state["json_file_path"] = json_file_path
    word_list = WORDLISTS[word_list]

    if scanner_type and LEFT.button(scanner_type, key="scantype"):
        scanner = scanners[scanner_type](target_url)
        RIGHT.text(f"{scanner_type.split(' Scanner')[0]} {target_url}")

        st.session_state["found_addresses"] = st.session_state.get("found_addresses", {"sites": {}})
        found_sites = st.session_state["found_addresses"]
        if target_url not in found_sites:
            found_sites[target_url] = {}

        if "subdomains" not in found_sites[target_url]:
            found_sites[target_url]["subdomains"] = {}

        if isinstance(scanner, SubdomainScanner):
            output = scanner.scan(target_url, word_list)
            found_sites[target_url]["subdomains"] = list(output)

        if "dirs" not in found_sites[target_url]:
            found_sites[target_url]["dirs"] = {}

        if isinstance(scanner, DirectoryScanner):
            output = scanner.scan(target_url, word_list)
            found_sites[target_url]["dirs"] = list(output)

        if isinstance(scanner, UrlParameterScanner):
            parameter_names  = parameters.get("objects",[])
            parameter_values = parameters.get("passwords",[])
            filtered_parameters = {k: v for k, v in parameters.items() if k in parameter_names}
            filtered_values = list(set(parameter for k, v in filtered_parameters.items() for parameter in v if parameter in parameter_values))
            output = scanner.scan(target_url, parameters=filtered_parameters, sites=filtered_values)
            found_sites[target_url]["parameters"] = list(output)

        with open(json_file_path, "w") as json_file:
            json.dump(found_sites, json_file)

        st.sidebar.write(found_sites)


if __name__ == "__main__":
    main()
