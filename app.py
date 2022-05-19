import base64

from unfurl import core
import hashlib
import html.parser
import re
import json
import time
import os
import socket
import strictyaml
import urllib.parse
import requests
from ipwhois import IPWhois
from googletrans import Translator
from pandas import read_csv
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from feature_extraction import feature_extraction
from sklearn.feature_extraction.text import TfidfVectorizer

from Modules import iplists
from Modules import phishtank
from Modules import TitleOpen
from datetime import datetime, date
print("Hello world")
import pickle
# import enchant
import ipaddress
import pandas as pd
import numpy as np

import sys
import argparse
import array
import math
import pefile
import hashlib
import yara
import joblib
import urllib
import urllib3
from requests.auth import HTTPBasicAuth
import colorama
import base64
import webbrowser


from flask import Flask, send_file, request, render_template, Markup, redirect, url_for
app = Flask(__name__)

UPLOAD_FOLDER = './uploads'
versionNo = '1.3.2'

try:
    f = open("config.yaml", "r")
    configvars = strictyaml.load(f.read())
    f.close()
except FileNotFoundError:
    print("Config.yaml not found. Check whether 'config.yaml' file is present or not with API Keys.")

linksFoundList = []
linksRatingList = []
linksSanitized = []
linksDict = {}

"""Ransomware Detection Section Starts"""
# Class to extract features from input file.
class ExtractFeatures():
    
    # Defining init method taking parameter file.
    def __init__(self, file):
        self.file = file

    # Method for extracting the MD5 hash of a file.
    # It is not always possible to fit the entire file into memory so chunks of
    # 4096 bytes are read and sequentially fed into the function.
    def get_md5(self, file):
        md5 = hashlib.md5()
        with open(file, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
            return md5.hexdigest()
    
    # Method for compiling the yara rule for searching files for
    # signs of bitcoin addresses. 
    def compile_bitcoin(self):
        if not os.path.isdir("rules_compiled/Bitcoin"):
            os.makedirs("rules_compiled/Bitcoin")
            print("success")

        for n in os.listdir("rules/Bitcoin"):
            rule = yara.compile("rules/Bitcoin/" + n)
            rule.save("rules_compiled/Bitcoin/" + n)
    
    # Method for checking the input file for any signs of embedded bitcoin
    # addresses. If the file does contain a bitcoin address a 1 is returned. 
    # Otherwise a 0 is returned.
    def check_bitcoin(self, file):
        self.compile_bitcoin()
        for n in os.listdir("rules/Bitcoin"):
            rule = yara.load("rules_compiled/Bitcoin/" + n)
            m = rule.match(file)
            if m:
                return 1
            else:
                return 0
    
    # Method for extracting all features from an input file.
    def get_fileinfo(self, file):
        # Creates a dictionary that will hold feature names as keys and 
        # their feature values as values.
        features = {}

        # Assigns pe to the input file. fast_load loads all directory 
        # information.
        pe = pefile.PE(file, fast_load=True)

        # CPU that the file is intended for.
        features['Machine'] = pe.FILE_HEADER.Machine

        # DebugSize is the size of the debug directory table. Clean files
        # typically have a debug directory and thus, will have a non-zero
        # values.
        features['DebugSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size

        # Debug Relative Virtual Address (RVA). 
        features['DebugRVA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].\
            VirtualAddress

        # MajorImageVersion is the version of the file. This is user defined
        # and for clean programs is often populated. Malware often has a
        # value of 0 for this.
        features['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion

        # MajorOSVersion is the major operating system required to run exe.
        features['MajorOSVersion'] = pe.OPTIONAL_HEADER.\
            MajorOperatingSystemVersion

        # Export Relative Virtual Address (VRA).
        features['ExportRVA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].\
            VirtualAddress

        # ExportSize is the size of the export table. Usually non-zero for
        # clean files.
        features['ExportSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size

        # IatRVA is the relative virtual address of import address
        # table. Clean files typically have 4096 for this where as malware
        # often has 0 or a very large number.
        features['IatVRA'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].\
            VirtualAddress

        # ResourcesSize is the size of resources section of PE header. 
        # Malware sometimes has 0 resources.
        features['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.\
            MajorLinkerVersion

        # MinorLinkerVersion is the minor version linker that produced the
        # file.
        features['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion

        # NumberOfSections is the number of sections in file.
        features['NumberOfSections'] = pe.FILE_HEADER.NumberOfSections 

        # SizeOfStackReserve denotes the amount of virtual memory to reserve
        # for the initial thread's stack.
        features['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve

        # DllCharacteristics is a set of flags indicating under which
        # circumstances a DLL's initialization function will be called.
        features['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics

        # ResourceSize denotes the size of the resources section.
        # Malware may often have no resources but clean files will.
        features['ResourceSize'] = pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size

        # Creates an object of Extract features and passes in the input
        # file. The object get_bitcoin accesses the check_bitcoin method
        # for which a 1 or 0 is returned and added as a value in the
        # dictionary.
        get_bitcoin = ExtractFeatures(file)
        bitcoin_check = get_bitcoin.check_bitcoin(file)
        features['BitcoinAddresses'] = bitcoin_check

        # Returns features for the given input file.
        return features

# Class to search third party reputation checkers and malware analysis
# websites to cross check if the tool is making correct decisions.
class RepChecker():

    # Init method to initalise api keys and base urls.
    def __init__(self):
        # Virus Total api key
        vtapi = base64.b64decode('M2FlNzgwMDU5MTE3ZThkYzdmNjA5YjVlOWU1Y2JmOTRkMGJkNTA3NTAyNzI3NWJiOTM3YTg0NGEwYTYzNDNlYQ==')
        self.vtapi = vtapi.decode('utf-8')
        # Virus Total base URL
        self.vtbase = 'https://www.virustotal.com/vtapi/v2/file/report'
        self.http = urllib3.PoolManager()
        # Threat Crowd base URL.
        self.tcbase = 'http://www.threatcrowd.org/searchApi/v2/file/report/?resource='
        # Hybrid Analysis api key.
        hapi = base64.b64decode('OGtzMDhrc3NrOGNja3Nnd3dnY2NnZzRzOG8wczA0Y2tzODA4c2NjYzAwZ2s0a2trZzRnc2s4Zzg0OGc4b2NvNA==')
        self.hapi = hapi.decode('utf-8')
        # Hybrid Analysis secret key.
        hsecret = base64.b64decode('MTFhYjc1OTMxZGYzOWFjMmVjYmI3ZGNhNmI1MzYxMmE3YmU4ZjM3MTM5YTAwY2Nm')
        self.hsecret = hsecret.decode('utf-8')
        # Hybrid Analysis base URL.
        self.hbase = 'https://www.hybrid-analysis.com/api/scan/'
    
    # Method for authenticating to Virus Total API and file information
    # in JSON. 
    def get_virus_total(self, md5):
        params = {'apikey': self.vtapi, 'resource':md5}
        data = urllib.parse.urlencode(params).encode("utf-8")
        r = requests.get(self.vtbase, params=params)
        return r.json()

    # Method for returning file information in JSON from
    # Threat Crowd.
    def get_threatcrowd(self, md5):
        r = requests.get(self.tcbase)
        return r.json()

    # Method for authenticating to Hybrid Analysis API and
    # returning file information in JSON.
    def get_hybrid(self, md5):
        headers = {'User-Agent': 'Falcon'}
        query = self.hbase + md5    
        r = requests.get(query, headers=headers, auth=HTTPBasicAuth(self.hapi, self.hsecret))
        return r.json()

# Open up survey to evaluate program.
def survey_mail():
    print('\n[*] Opening up survey in browser.\n')
    webbrowser.open('https://www.surveymonkey.de/r/N289B82', new=2)

# Function to parse user input. Takes in input file, extracted features,
# and parsed options.
def parse(file, features, display, virustotal, threatcrowd, hybridanalysis):
    # Creates an object of RepChecker to return third party about 
    # input file.
    get_data = RepChecker()
    # Creates an object of ExtractFeatures to return information about the
    # input file. 
    md5 = ExtractFeatures(file)
    md5_hash = md5.get_md5(file)
   
    # If display option is selected, the extracted features are printed
    # to the screen. 
    if display:
        print("[*] Printing extracted file features...")
        print("\n\tMD5: ", md5_hash)
        print("\tDebug Size: ", features[0])
        print("\tDebug RVA: ", features[1])
        print("\tMajor Image Version:", features[2])
        print("\tMajor OS Version:", features[3])
        print("\tExport RVA:", features[4])
        print("\tExport Size:", features[5])
        print("\tIat RVA: ", features[6])
        print("\tMajor Linker Version: ", features[7])
        print("\tMinor Linker Version", features[8])
        print("\tNumber Of Sections: ", features[9])
        print("\tSize Of Stack Reserve: ", features[10])
        print("\tDll Characteristics: ", features[11])
        if features[12] == 1:
            print("\tBitcoin Addresses: Yes\n")
        else: 
            print("\tBitcoin Addresses: No\n")

    # If Virus Total option is selected, file information from Virus
    # total is returned.
    if virustotal:
        print("[+] Running Virus Total reputation check...\n")
        # Retrieves data from virus total. Searches by passing in
        # md5 hash of input file.
        data = get_data.get_virus_total(md5_hash)

        # If the response code is 0, error message is returned indicating 
        # that the md5 hash is not in virus total. Otherwise, the number
        # of AV companies that detected the file as malicious is returned
        # If 0, output is in green. 
        # Between 0 and 25, output is yellow.
        # Over 25, output is red.
        if data['response_code'] == 0:
            print("[-] The file %s with MD5 hash %s was not found in Virus Total" % (os.path.basename(file), md5_hash))
        else:
            print("\tResults for file %s with MD5 %s:" % (os.path.basename(file), md5_hash))
            if data['positives'] == 0:
                print("\n\tDetected by: ", colored(str(data['positives']), 'green'), '/', data['total'], '\n')
            elif data['positives'] > 0 and data['positives'] <= 25:
                print("\n\tDetected by: ", colored(str(data['positives']), 'yellow'), '/', data['total'], '\n')
            else:
                print("\n\tDetected by: ", colored(str(data['positives']), 'red'), '/', data['total'], '\n')

            # Creates two lists to store the AV companies who detected the file
            # as malicious and to store corresponding malware names.
            av_firms = []
            malware_names = []
            fmt = '%-4s%-23s%s'

            # If any AV company indicated that the file is malicious, it is
            # printed to the screen. 
            if data['positives'] > 0:  
                for scan in data['scans']:
                    if data['scans'][scan]['detected'] == True:
                        av_firms.append(scan)
                        malware_names.append(data['scans'][scan]['result'])

                print('\t', fmt % ('', 'AV Firm', 'Malware Name'))
                for i, (l1, l2) in enumerate(zip(av_firms, malware_names)):
                    print('\t', fmt % (i, l1, l2))
                if data['permalink']:
                    print("\n\tVirus Total Report: ", data['permalink'], '\n') 

            # Prints if Virus Total has found the file to be malicious.
            if data['positives'] == 0:
                print(colored('[*] ', 'green') + "Virus Total has found the file %s " % os.path.basename(file) + colored("not malicious.", 'green'))        
                if data['permalink']:
                    print("\n\tVirus Total Report: ", data['permalink'], '\n')
            elif data['positives'] > 0 and data['positives'] <= 25:
                print(colored('[*] ', 'red') + "Virus Total has found the file %s " % os.path.basename(file) + colored("has malicious properties.\n", 'yellow'))       
            else:
                print(colored('[*] ', 'red') + "Virus Total has found the file %s " % os.path.basename(file) + colored("is malicious.\n", 'red'))       

    # If threat crowd option is selected, file information is returned.            
    if threatcrowd:
        fmt = '%-4s%-23s'
        print("[+] Retrieving information from Threat Crowd...\n")
        data = get_data.get_threatcrowd(md5_hash)            
        
        # If response code is 0, an error message is thrown to indicate
        # the file is not in Threat Crowd. Otherwise, the SHA1 Hash,
        # domain names, and malware names given by AV companies for
        # the file is printed to the screen.
        if data['response_code'] == "0":
            print("[-] The file %s with MD5 hash %s was not found in Threat Crowd.\n" % (os.path.basename(file), md5_hash))
        else:
            print("\n\tSHA1: ", data['sha1'])
            if data['ips']:
                print('\n\t', fmt % ('', 'IPs'))
                for i, ip in enumerate((data['ips'])):
                    print('\t', fmt % (i+1, ip))

            if data['domains']:
                print('\n\t', fmt % ('', 'Domains'))
                for i, domain in enumerate((data['domains'])):
                    print('\t', fmt % (i+1, domain))
                    
            if data['scans']:
                if data['scans'][1:]:
                    print('\n\t', fmt % ('', 'Antivirus'))
                    for i, scan in enumerate(data['scans'][1:]):
                        print('\t', fmt % (i+1, scan))
            
            print('\n\tThreat Crowd Report: ', data['permalink'], '\n')

    # If hybrid analysis option is selected, file information is returned.
    if hybridanalysis:
        # Searches hybrid analysis with md5 hash of file and attempts
        # to return its information in JSON format.
        data = get_data.get_hybrid(md5_hash)  
        fmt = '%-4s%-23s'

        print("[+] Retrieving information from Hybrid Analysis...\n")

        # If no response, error message is thrown to indicate that the file
        # is not in Hybrid Analysis. Otherwise, SHA256, SHA1, Threat Level,
        # Threat Score, Verdict (malicious / not malicious), malware family,
        # and network information is returned
        if not data['response']:
            print("[-] The file %s with MD5 hash %s was not found in Hybrid Analysis." % (os.path.basename(file), md5_hash), '\n')
        else:
            try:
                print('\t', data['response'][0]['submitname'])
            except:
                pass

            print('\tSHA256:', data['response'][0]['sha256'])
            print('\tSHA1: ', data['response'][0]['sha1'])
            print('\tThreat Level: ', data['response'][0]['threatlevel'])
            print('\tThreat Score: ', data['response'][0]['threatscore'])
            print('\tVerdict: ', data['response'][0]['verdict'])
            
            try:
                print('\tFamily: ', data['response'][0]['vxfamily'])
            except:
                pass
            try:
                if data['response'][0]['classification_tags']:
                    print('\n\t', fmt % ('', 'Class Tags'))
                    for i, tag in enumerate(data['response'][0]['classification_tags']):
                        print('\t', fmt % (i+1, tag))
                else:
                    print("\tClass Tags: No Classification Tags.")
            except:
                pass            
            try:
                if data['response'][0]['compromised_hosts']:
                    print('\n\t', fmt % ('', 'Compromised Hosts'))
                    for i, host in enumerate(data['response'][0]['compromised_hosts']):
                        print('\t', fmt % (i+1, host))
                else: 
                    print('\t\nCompromised Hosts: No Compromised Hosts.')
            except:
                pass
            try:
                if data['response'][0]['domains']:
                    print('\n\t', fmt % ('', 'Domains'))
                    for i, domain in enumerate(data['response'][0]['domains']):
                        print('\t', fmt % (i+1, domain))
                else:
                    print('\tDomains: No Domains.')
            except:
                pass
            try:
                if data['response'][0]['total_network_connections']:
                    print('\tNetwork Connections: ', data['response'][0]['total_network_connections'])
                else:
                    print('\n\tNetwork Connections: No Network Connections')
            except:
                pass
            try:
                if data['response'][0]['families']:
                    print('\tFamilies: ', data['response'][0]['families'])
            except:
                pass
            if data['response'][0]['verdict'] == "malicious":
                print(colored('\n[*] ', 'red') + "Hybrid Analysis has found that the file %s " % os.path.basename(file) + colored("is malicious.\n", 'red'))       
            else:
                print(colored('\n[*] ', 'green') + "Hybrid Analysis has found that the file %s " % os.path.basename(file) + colored("is not malicious.\n", 'green'))  

def checkransomware(file):
    headingText = "ML Ransomware Detection Result"
    returnedHTML = ""
    colorama.init()
    # Loads classifier
    clf = joblib.load(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/classifier.pkl'))    
    # Loads saved features
    features = pickle.loads(open(os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        'classifier/features.pkl'),
        'rb').read())
    # Creates an object of ExtractFeatures and passes in input file.
    get_features = ExtractFeatures(file)
    # Assigns data to extracted features 
    data = get_features.get_fileinfo(file)
    feature_list = list(map(lambda x:data[x], features))
    print("\n[+] Running analyzer...\n")
    # Asssings result as the prediction of the input file based on its given features.
    result = clf.predict([feature_list])[0]
    # If result is 1, the file is benign.
    # Otherwise, the file is malicious.
    if result == 1:
        returnedHTML += "<h5>The uploaded file has been identified as Normal. No ransomware detected.</h5>"
    else:
        returnedHTML += "<h5>Ransomware Detected. Please DON'T execute this file. It's malacious!</h5>"
    return headingText,returnedHTML

"""Ransomware Detection Section Ends"""

"""DOMAIN ANALYZER PORTION STARTS"""
# for calculating the main domain length. will run after the function MLD()
def MLD(domain):
    if domain.split(".")[0].startswith("ww"):
        mld = domain.split(".")[1]
    else:
        mld = domain.split(".")[0]
    print(mld)
    return mld

# calculating hiphens in the domain
def NoHiphen(domain):
    count = 0
    for each in domain:
        if each == "-":
            count = count + 1
    return count

# calculating underscores in the domain
def NoUnderscore(domain):
    count = 0
    for each in domain:
        if each == "_":
            count = count + 1
    return count

# if ipaddress present in the domain
def IPPresent(domain):
    try:
        ipaddress.ip_address(domain)
        ip_present = 1
    except:
        ip_present = 0
    return ip_present

# number of digits present in the domain
def numDigits(domain):
    digits = [i for i in domain if i.isdigit()]
    return len(digits)

def lenFLD(domain):
    full_dataset = dataset_sinkhole.values.tolist()
    list_main_domain = [each[0] for each in full_dataset]
    len_fld = []
    for domain in list_main_domain:
        len_fld.append(len(domain))

def vowel_consonant_ratio(domain):
    vowels = 0
    consonants = 0
    for letter in domain:
        if (letter == "."):
            continue
        elif (
                letter == 'a' or letter == 'e' or letter == 'i' or letter == 'o' or letter == 'u' or letter == 'A' or letter == 'E'
                or letter == 'I' or letter == 'O' or letter == 'U'):
            vowels = vowels + 1
        else:
            consonants = consonants + 1
    return round(vowels / consonants, 2)

def unique_character_ratio(domain):
    unique_character_ratio = []
    unique_length = len(set(domain))
    total_length = len(domain)
    return round(unique_length / total_length, 2)

def number_character_ratio(domain):
    count_digit = 0
    digits = [i for i in domain if i.isdigit()]
    count_digit = (len(digits))
    return (round(count_digit / (len(domain) - count_digit), 2))

def entropy(st):  # reference:http://code.activestate.com/recipes/577476-shannon-entropy-calculation/
    import math
    # pld input string
    # st = '00010101011110' # Shannon entropy for this would be 1 bit/symbol

    stList = list(st)
    alphabet = list(set(stList))  # list of symbols in the string

    # calculate the frequency of each symbol in the string
    freqList = []
    for symbol in alphabet:
        ctr = 0
        for sym in stList:
            if sym == symbol:
                ctr += 1
        freqList.append(float(ctr) / len(stList))
    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        ent = ent + freq * math.log(freq, 2)
    ent = -ent
    return ent
    # print('Shannon entropy:')
    # print(ent)
    # print('Minimum number of bits required to encode each symbol:')
    # print(int(math.ceil(ent)))

def dict_domain(PLD):
    try:
        if (d.check(PLD)):
            dictDomain = 1
        else:
            dictDomain = 0
    except Exception as e:
        print(str(e))
    return dictDomain

def IsFirstCharNumber(domain):
    if domain[0].isdigit():
        isDigit = 1
    else:
        isDigit = 0
    return isDigit

def analyze_domain(domain):
    domain=domain.strip("\"")
    if domain.split(".")[0].startswith("ww"):
        domain = domain.replace("www.", "", 1)
    d = {}
    # d = enchant.Dict("en_US")
    var_MLD = MLD(domain)
    NoDS = len(domain.split('.'))
    Entropy = round(entropy(domain), 2)
    var_vowel_consonant_ratio = vowel_consonant_ratio(domain)
    var_No_Char_Ratio = number_character_ratio(domain)
    var_NoDigits = numDigits(domain)
    dictDomain = dict_domain(var_MLD)
    LenMLD = len(var_MLD)
    var_NoHiphen = NoHiphen(domain)
    var_NoUnderscore = NoUnderscore(domain)
    var_IPPresent = IPPresent(domain)
    var_unique_character_ratio = unique_character_ratio(domain)
    var_firstchar = IsFirstCharNumber(domain)
    predicted_pronounce = xg_pronoun.predict([domain])

    input_predict_domain = np.array([[NoDS, dictDomain, Entropy, var_vowel_consonant_ratio, var_No_Char_Ratio, var_NoDigits, LenMLD, var_NoHiphen, var_NoUnderscore, var_IPPresent, var_unique_character_ratio, predicted_pronounce[0], var_firstchar]]).astype(float)
    # print(input_predict_domain)
    # print(domain)

    input_array = pd.DataFrame(input_predict_domain,
                                columns=['NoDS', 'dictDomain', 'Entropy', 'vowel_consonant_ratio', 'No_Char_Ratio',
                                        'NoDigits', 'LenMLD', 'NoHiphen', 'NoUnderscore', 'IPPresent',
                                        'unique_character_ratio', 'pronounceability_score', 'FirstCharNumber'])
    input_array = input_array.iloc[:, :].values
    input_array = xg_scaler.transform(input_array.reshape(1, -1))

    predict_suspicious_domain = xg_domain.predict_proba(input_array)
    # print(predict_suspicious_domain)
    result = str(round(predict_suspicious_domain[0][0] * 100, 4)) + '%'
    headingText = "Domain Analyzer Result"
    returnedHTML = "<b>The probability of domain being suspicious is: </b>"+result
    return headingText,returnedHTML

def analyze_url_ml(url):
    url = url.strip("\"")
    url = url.lstrip("https://")
    url = url.lstrip("http://")
    url = url.lstrip("www.")
    url = url.rstrip("\\")
    value = vectorizer.transform([url])
    predict_suspicious_url = logreg_url.predict_proba(value)
    result = str(round(predict_suspicious_url[0][0] * 100, 4)) + ' %'
    headingText = "ML URL Analyzer Result"
    returnedHTML = "<b>The probability of URL being suspicious is: </b>"+result
    return headingText,returnedHTML

"""DOMAIN ANALYZER PORTION ENDS"""


def analyzeEmail(email):
    returnedHTML = ""
    try:
        url = 'https://emailrep.io/'
        userAgent ='rachkuma'
        summary = '?summary=true'
        url = url + email + summary
        if 'API Key' not in configvars.data['EMAILREP_API_KEY']:
            erep_key = configvars.data['EMAILREP_API_KEY']
            headers = {'Content-Type': 'application/json', 'Key': configvars.data['EMAILREP_API_KEY'], 'User-Agent': userAgent}
            response = requests.get(url, headers=headers)
        else:
            response = requests.get(url)
        req = response.json()
        emailDomain = re.split('@', email)[1]
        returnedHTML += ' <h4>Email Analysis Report </h4><br>'
        if response.status_code == 400:
            returnedHTML += '<b> Invalid Email / Bad Request</b><br>'
        if response.status_code == 401:
            returnedHTML += '<b> Unauthorized / Invalid API Key (for Authenticated Requests)</b><br>'
        if response.status_code == 429:
            returnedHTML += '<b>Too many requests, </b><br>'
        if response.status_code == 200:
            returnedHTML = returnedHTML + '<p><b>   Email:       </b>' + str(req['email']) + '</p>'
            returnedHTML = returnedHTML + '<p><b>   Reputation:  </b>' + str(req['reputation']) + '</p>'
            returnedHTML = returnedHTML + '<p><b>   Suspicious:  </b>' + str(req['suspicious']) + '</p>'
            returnedHTML = returnedHTML + '<p><b>   Spotted:     </b>' + str(req['references']) + ' Times' + '</p>'
            returnedHTML = returnedHTML + '<p><b>   Blacklisted: </b>' + str(req['details']['blacklisted']) + '</p>'
            returnedHTML = returnedHTML + '<p><b>   Last Seen:   </b>' + str(req['details']['last_seen']) + '</p>'
            returnedHTML = returnedHTML + '<p><b>   Known Spam:  </b>' + str(req['details']['spam'])+'</p><br><br>'

            returnedHTML += '<h4>Domain Report</h4><br> '
            returnedHTML = returnedHTML +  '<p><b>   Domain:        </b>' + emailDomain + '<br>'
            returnedHTML = returnedHTML +  '<p><b>   Domain Exists: </b>' + str(req['details']['domain_exists']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Domain Rep:    </b>' + str(req['details']['domain_reputation']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Domain Age:    </b>' + str(req['details']['days_since_domain_creation']) + ' Days' + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   New Domain:    </b>' + str(req['details']['new_domain']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Deliverable:   </b>' + str(req['details']['deliverable']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Free Provider: </b>' + str(req['details']['free_provider']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Dispos able:   </b>' + str(req['details']['disposable']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Spoofable:     </b>' + str(req['details']['spoofable']) + '</p><br><br>'


            returnedHTML = returnedHTML +  '<h4>Malicious Activity Report</h4> ' + '<br>'
            returnedHTML = returnedHTML +  '<p><b>   Malicious Activity: </b>' + str(req['details']['malicious_activity']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Recent Activity:    </b>' + str(req['details']['malicious_activity_recent']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Credentials Leaked: </b>' + str(req['details']['credentials_leaked']) + '</p>'
            returnedHTML = returnedHTML +  '<p><b>   Found in breach:    </b>' + str(req['details']['data_breach']) + '</p><br><br>'

            returnedHTML += '<h4>Profiles Found</h4><br> '
            if (len(req['details']['profiles']) != 0):
                profileList = (req['details']['profiles'])
                for each in profileList:
                    returnedHTML = returnedHTML + '<p><b>'+ str(each)  +'</b></p>'
            else:
                returnedHTML += '<b>   No Profiles Found For This User</b><br><br><br>'

            returnedHTML += '<h4>Summary of Report: </h4><br>'
            repSum = req['summary']
            repSum = re.split(r"\.\s*", repSum)
            for each in repSum:
                returnedHTML = returnedHTML + '<p><b>'+ str(each)  +'</b></p>'
            returnedHTML+="<br><br><br>"
        return returnedHTML
    except(error):
        returnedHTML += '<h4>Error Analyzing Submitted Email</h4>'
        return returnedHTML


def repChecker(rawInput):
    headingText = 'Reputation Checker Result'
    returnedHTML = ''
    rawInput = rawInput.split()
    ip = str(rawInput[0])
    s = re.findall(r'\S+@\S+', ip)
    if s:
        returnedHTML += '<h3> Email Detected...</h3><br>'
        returnedHTML += analyzeEmail(''.join(s))
    else:
        wIP = socket.gethostbyname(ip)
        returnedHTML += '<h3>  VirusTotal Report:</h3><br>'
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': configvars.data['VT_API_KEY'], 'resource': wIP}
        response = requests.get(url, params=params)
        pos = 0 # Total positives found in VT
        tot = 0 # Total number of scans
        if response.status_code == 200:
            try:
                result = response.json()
                for each in result:
                    tot = result['total']
                    if result['positives'] != 0:
                        pos = pos +1
                avg = pos/tot
                returnedHTML = returnedHTML + "<p><b>   No of Databases Checked: </b>" + str(tot) + "</p>"
                returnedHTML = returnedHTML + "<p><b>   No of Reportings:        </b>" + str(pos) + "</p>"
                returnedHTML = returnedHTML + "<p><b>   Average Score:           </b>" + str(avg) + "</p>"
                temp_link = "<a href = \""+str(result['permalink']) +"\" target=\"_blank\"> Link</a>"
                returnedHTML = returnedHTML + "<p><b>   VirusTotal Report Link:  </b>" + temp_link + "</p><br><br>"
            except:
                returnedHTML += "<b>Error</b><br>"
        else:
            returnedHTML += "<b>There's been an error, check your API Key or VirusTotal may be down!</b><br><br>"
    returnedHTML += "<h3> Checking BadIP's...</h3><br> "

    try:
        BAD_IPS_URL = 'https://www.badips.com/get/info/' + wIP
        response = requests.get(BAD_IPS_URL)
        if response.status_code == 200:
            result = response.json()
            returnedHTML = returnedHTML + "<p><b>  </b>" + str(result['suc']) + "</p>"
            returnedHTML = returnedHTML + "<p><b>  Total Reports : </b>" + str(result['ReporterCount']['sum']) + "</p>"
            returnedHTML = returnedHTML + "<p><b>  IP has been reported in the following Categories:</b>" + "</p>"
            for each in result['LastReport']:
                timeReport = datetime.fromtimestamp(result['LastReport'].get(each))
                returnedHTML = returnedHTML + '<p><b>   - </b>' + each + ': ' + str(timeReport)+'</p>'
            returnedHTML += "<br><br>"
        else:
            returnedHTML += "<b>Error reaching BadIPs</b><br>"
    except:
        returnedHTML += "IP not found<br><br><br>"

    returnedHTML += "<h3> ABUSE IP DB Report:</h3><br>"

    try:
        AB_URL = 'https://api.abuseipdb.com/api/v2/check'
        days = '180'

        querystring = {
            'ipAddress': wIP,
            'maxAgeInDays': days
        }

        headers = {
            'Accept': 'application/json',
            'Key': configvars.data['AB_API_KEY']
        }
        response = requests.request(method='GET', url=AB_URL, headers=headers, params=querystring)
        if response.status_code == 200:
            req = response.json()

            returnedHTML = returnedHTML + "<p><b>   IP:          </b>" + str(req['data']['ipAddress']) + "</p>"
            returnedHTML = returnedHTML + "<p><b>   Reports:     </b>" + str(req['data']['totalReports']) + "</p>"
            returnedHTML = returnedHTML + "<p><b>   Abuse Score: </b>" + str(req['data']['abuseConfidenceScore']) + "%" + "</p>"
            returnedHTML = returnedHTML + "<p><b>   Last Report: </b>" + str(req['data']['lastReportedAt']) + "</p><br><br>"
        else:
            returnedHTML += "<b>Error Reaching ABUSE IPDB</b><br>"
    except:
        returnedHTML += "<b>IP Not Found</b><br>"
    return headingText,returnedHTML


def urlDecoder(url):
    decodedUrl = urllib.parse.unquote(str(url).strip())
    return decodedUrl

def unshortenUrl(url):
    req = requests.get(str('https://unshorten.me/s/' + str(url).strip()))
    print("hello I am in unShortened URL method \n")
    return req.text

def unfurlUrl(url):
    url_to_unfurl = str(url).strip()
    unfurl_instance = core.Unfurl()
    unfurl_instance.add_to_queue(data_type='url', key=None, value=url_to_unfurl)
    unfurl_instance.parse_queue()
    return r'{0}'.format(unfurl_instance.generate_text_tree())

def proofPointDecoder(link):
    rewrittenurl = link.strip()
    match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', rewrittenurl)
    matchv3 = re.search(r'urldefense.com/(v3)/', rewrittenurl)
    result = ""
    if match:
        if match.group(1) == 'v1':
            decodev1(rewrittenurl)
            for each in linksFoundList:
                result+=" <br><b>Decoded Link:</b> {}".format(each)
                linksFoundList.clear()
        elif match.group(1) == 'v2':
            decodev2(rewrittenurl)
            for each in linksFoundList:
                result+=" <br><b>Decoded Link:</b> {}".format(each)
                linksFoundList.clear()

    if matchv3 is not None:
        if matchv3.group(1) == 'v3':
            decodev3(rewrittenurl)
            for each in linksFoundList:
                result+=" <br><b>Decoded Link:</b> {}".format(each)
                linksFoundList.clear()
        else:
            result+= " No valid URL found in input: {}".format(rewrittenurl)
    return result

def urlscanio(url,type):
    url_to_scan = str(url).strip()

    try:
        # type_prompt = str(input('\nSet scan visibility to Public? \nType "1" for Public or "2" for Private: '))
        type_prompt = type
        if type_prompt == '1':
            scan_type = 'public'
        else:
            scan_type = 'private'
    except:
        print('Please make a selection again.. ')

    headers = {
        'Content-Type': 'application/json',
        'API-Key': configvars.data['URLSCAN_IO_KEY'],
    }

    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data='{"url": "%s", "%s": "on"}' % (url_to_scan, scan_type)).json()

    try:
        if 'successful' in response['message']:
            print('\nNow scanning %s. Check back in around 1 minute.' % url_to_scan)
            uuid_variable = str(response['uuid']) # uuid, this is the factor that identifies the scan
            time.sleep(45) # sleep for 45 seconds. The scan takes awhile, if we try to retrieve the scan too soon, it will return an error.
            scan_results = requests.get('https://urlscan.io/api/v1/result/%s/' % uuid_variable).json() # retrieving the scan using the uuid for this scan

            task_url = scan_results['task']['url']
            verdicts_overall_score = scan_results['verdicts']['overall']['score']
            verdicts_overall_malicious = scan_results['verdicts']['overall']['malicious']
            task_report_URL = scan_results['task']['reportURL']

            print("\nurlscan.io Report:")
            heading = "urlscan.io Report:"
            print("\nURL: " + task_url)
            urlDisplay = "<b>URL:</b> " + task_url
            print("\nOverall Verdict: " + str(verdicts_overall_score))
            overallVerdict = "<b>Overall Verdict:</b> " + str(verdicts_overall_score)
            print("Malicious: " + str(verdicts_overall_malicious))
            malicious = "<b>Malicious:</b> " + str(verdicts_overall_malicious)
            print("urlscan.io: " + str(scan_results['verdicts']['urlscan']['score']))
            urlscanScore = "<b>urlscan.io:</b> " + str(scan_results['verdicts']['urlscan']['score'])
            if scan_results['verdicts']['urlscan']['malicious']:
                print("Malicious: " + str(scan_results['verdicts']['urlscan']['malicious'])) # True
            if scan_results['verdicts']['urlscan']['categories']:
                print("Categories: ")
            for line in scan_results['verdicts']['urlscan']['categories']:
                print("\t"+ str(line)) # phishing
            for line in scan_results['verdicts']['engines']['verdicts']:
                print(str(line['engine']) + " score: " + str(line['score'])) # googlesafebrowsing
                print("Categories: ")
                for item in line['categories']:
                    print("\t" + item) # social_engineering
            print("\nSee full report for more details: " + str(task_report_URL))
            fullreportLink = "<b>See full report for more details:</b>    " + "<a href = \""+str(task_report_URL) +"\" target=\"_blank\"> Link</a>"
            print('')
            return heading,urlDisplay,overallVerdict,malicious,urlscanScore,fullreportLink
        else:
            print(response['message'])
    except:
        print(' Error reaching URLScan.io')

def urlSanitise(url):
    url = url.strip()
    x = re.sub(r"\.", "[.]", url)
    x = re.sub("http://", "hxxp://", x)
    x = re.sub("https://", "hxxps://", x)
    return x

def safelinksDecoder(url):
    url = url.strip()
    dcUrl = urllib.parse.unquote(url)
    dcUrl = dcUrl.replace('https://nam02.safelinks.protection.outlook.com/?url=', '')
    return dcUrl

def b64Decoder(url):
    url = url.strip()
    try:
        b64 = str(base64.b64decode(url))
        a = re.split("'", b64)[1]
        return a
    except:
        return "No Base64 Encoded String Found or the provided b64 string can't be decoded!"

def translateLanguage(text):
    LANGUAGES = {
        'af': 'afrikaans',
        'sq': 'albanian',
        'am': 'amharic',
        'ar': 'arabic',
        'hy': 'armenian',
        'az': 'azerbaijani',
        'eu': 'basque',
        'be': 'belarusian',
        'bn': 'bengali',
        'bs': 'bosnian',
        'bg': 'bulgarian',
        'ca': 'catalan',
        'ceb': 'cebuano',
        'ny': 'chichewa',
        'zh-cn': 'chinese (simplified)',
        'zh-tw': 'chinese (traditional)',
        'co': 'corsican',
        'hr': 'croatian',
        'cs': 'czech',
        'da': 'danish',
        'nl': 'dutch',
        'en': 'english',
        'eo': 'esperanto',
        'et': 'estonian',
        'tl': 'filipino',
        'fi': 'finnish',
        'fr': 'french',
        'fy': 'frisian',
        'gl': 'galician',
        'ka': 'georgian',
        'de': 'german',
        'el': 'greek',
        'gu': 'gujarati',
        'ht': 'haitian creole',
        'ha': 'hausa',
        'haw': 'hawaiian',
        'iw': 'hebrew',
        'he': 'hebrew',
        'hi': 'hindi',
        'hmn': 'hmong',
        'hu': 'hungarian',
        'is': 'icelandic',
        'ig': 'igbo',
        'id': 'indonesian',
        'ga': 'irish',
        'it': 'italian',
        'ja': 'japanese',
        'jw': 'javanese',
        'kn': 'kannada',
        'kk': 'kazakh',
        'km': 'khmer',
        'ko': 'korean',
        'ku': 'kurdish (kurmanji)',
        'ky': 'kyrgyz',
        'lo': 'lao',
        'la': 'latin',
        'lv': 'latvian',
        'lt': 'lithuanian',
        'lb': 'luxembourgish',
        'mk': 'macedonian',
        'mg': 'malagasy',
        'ms': 'malay',
        'ml': 'malayalam',
        'mt': 'maltese',
        'mi': 'maori',
        'mr': 'marathi',
        'mn': 'mongolian',
        'my': 'myanmar (burmese)',
        'ne': 'nepali',
        'no': 'norwegian',
        'or': 'odia',
        'ps': 'pashto',
        'fa': 'persian',
        'pl': 'polish',
        'pt': 'portuguese',
        'pa': 'punjabi',
        'ro': 'romanian',
        'ru': 'russian',
        'sm': 'samoan',
        'gd': 'scots gaelic',
        'sr': 'serbian',
        'st': 'sesotho',
        'sn': 'shona',
        'sd': 'sindhi',
        'si': 'sinhala',
        'sk': 'slovak',
        'sl': 'slovenian',
        'so': 'somali',
        'es': 'spanish',
        'su': 'sundanese',
        'sw': 'swahili',
        'sv': 'swedish',
        'tg': 'tajik',
        'ta': 'tamil',
        'te': 'telugu',
        'th': 'thai',
        'tr': 'turkish',
        'uk': 'ukrainian',
        'ur': 'urdu',
        'ug': 'uyghur',
        'uz': 'uzbek',
        'vi': 'vietnamese',
        'cy': 'welsh',
        'xh': 'xhosa',
        'yi': 'yiddish',
        'yo': 'yoruba',
        'zu': 'zulu'
    }
    translator = Translator()
    result = translator.translate(text)
    sourceLanguage = LANGUAGES[result.src]
    translation = result.text
    headingText = "Translation Result"
    returnedHTML = "<b>Detected Language: </b>"+sourceLanguage+"<br><b>Translated Text: </b>"+translation
    return headingText,returnedHTML

def scanPDFFile(file):
    df = read_csv('pdfdataset_n.csv')
    X = df.iloc[:, 0: 21]
    y = df.iloc[:, 21]
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

    #Running Random Forest Algorithm
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    acs = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    features = feature_extraction(file)
    result = clf.predict(features)
    heading = "Scanning PDF Completed!"
    resultHTML = "<b>Is PDF Malicious? : </b>"+result[0]+"<br><b>Accuracy of Detection: </>"+str(acs*100)[:4]+"%"
    return heading,resultHTML

def reverse_dns_lookup(ip):
    d = str(ip.strip())
    try:
        s = socket.gethostbyaddr(d)
        output = s[0]
    except:
        output = " Hostname not found"
    headingText = "Result"
    returnedHTML = "<b>"+output+"</b>"
    return headingText,returnedHTML

def download_file(filepath):
    return send_file(filepath, as_attachment=True)

def dnsLookup(domain):
    d = str(domain.strip())
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        output = s
    except:
        output = "Website not found"
    headingText = "Result"
    returnedHTML = "<b>"+output+"</b>"
    return headingText,returnedHTML

def whois_lookup(ip):
    d = str(ip.strip())
    returnedHTML = ""
    try:
        w = IPWhois(ip)
        w = w.lookup_whois()
        addr = str(w['nets'][0]['address'])
        addr = addr.replace('\n', ', ')
        print("\n WHO IS REPORT:")
        returnedHTML += " <b> CIDR: </b>     " + str(w['nets'][0]['cidr']) + "<br>"
        returnedHTML += "<b>Name:      </b>" + str(w['nets'][0]['name']) + "<br>"
        returnedHTML += "<b>Range:     </b>" + str(w['nets'][0]['range']) + "<br>"
        returnedHTML += "<b>Descr:     </b>" + str(w['nets'][0]['description']) + "<br>"
        returnedHTML += "<b>Country:   </b>" + str(w['nets'][0]['country']) + "<br>"
        returnedHTML += "<b>State:     </b>" + str(w['nets'][0]['state']) + "<br>"
        returnedHTML += "<b>City:      </b>" + str(w['nets'][0]['city']) + "<br>"
        returnedHTML += "<b>Address:   </b>" + addr + "<br>"
        returnedHTML += "<b>Post Code: </b>" + str(w['nets'][0]['postal_code']) + "<br>"
        returnedHTML += "<b>Created:   </b>" + str(w['nets'][0]['created']) + "<br>"
        returnedHTML += "<b>Updated:   </b>" + str(w['nets'][0]['updated']) + "<br>"

        now = datetime.now() # current date and time
        today = now.strftime("%m-%d-%Y")
        if not os.path.exists('output/'+today):
            os.makedirs('output/'+today)
        f= open('output/'+today+'/'+str(ip.split()) + ".txt","a+")
        file = 'output/'+today+'/'+str(ip.split()) + ".txt"
        f.write("\n ---------------------------------")
        f.write("\n WHO IS REPORT:")
        f.write("\n ---------------------------------\n")
        f.write("\n CIDR:      " + str(w['nets'][0]['cidr']))
        f.write("\n Name:      " + str(w['nets'][0]['name']))
        f.write("\n Range:     " + str(w['nets'][0]['range']))
        f.write("\n Descr:     " + str(w['nets'][0]['description']))
        f.write("\n Country:   " + str(w['nets'][0]['country']))
        f.write("\n State:     " + str(w['nets'][0]['state']))
        f.write("\n City:      " + str(w['nets'][0]['city']))
        f.write("\n Address:   " + addr)
        f.write("\n Post Code: " + str(w['nets'][0]['postal_code']))
        f.write("\n Created:   " + str(w['nets'][0]['created']))
        f.write("\n Updated:   " + str(w['nets'][0]['updated']))
        f.close();
        c = 0
        download_file(file)
        print("downloaded \n")
    except:
        output = " Hostname not found"
    output = "test output"
    headingText = "WhoIs Scanned Result"
    return headingText,returnedHTML

def checkFileHash(file):
    hasher = hashlib.md5()
    with open(file, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    fileHash = hasher.hexdigest()
    returnedHTML = ""
    returnedHTML+="<b>MD5 Hash: </b>"+str(fileHash)+"<br>"
    apierror = False
    # VT Hash Checker
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")
    if not apierror:
        if result['response_code'] == 0:
            returnedHTML += "<b>Hash was not found in Malware Database</b>"
        elif result['response_code'] == 1:
            returnedHTML = returnedHTML + " <b>VirusTotal Report: </b>" + str(result['positives']) + "/" + str(result['total']) + " detections found. <br>"
            returnedHTML = returnedHTML + " <b>Report Link: </b>" + "<a href = \""+str("https://www.virustotal.com/gui/file/" + fileHash + "/detection") +"\" target=\"_blank\"> Link</a>"
        else:
            print("No Response")
    headingText = "Hashing Result of Uploaded File"
    return headingText,returnedHTML

def getHashReport(fileHash):
    apierror = False
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")
    returnedHTML = ""
    if not apierror:
        if result['response_code'] == 0:
            returnedHTML += "<b>Hash was not found in Malware Database</b>"
        elif result['response_code'] == 1:
            returnedHTML = returnedHTML + " <b>VirusTotal Report: </b>" + str(result['positives']) + "/" + str(result['total']) + " detections found. <br>"
            returnedHTML = returnedHTML + " <b>Report Link: </b>" + "<a href = \""+str("https://www.virustotal.com/gui/file/" + fileHash + "/detection") +"\" target=\"_blank\"> Link</a>"
        else:
            print("No Response")
    headingText = "Report of Hashed Entered!"
    return headingText,returnedHTML

"""
HOME PAGE SECTION
"""
@app.route('/', methods=["GET", "POST"])
def landingPage():
    return render_template('index.html')

@app.route('/decoder', methods=["GET", "POST"])
def decoder():
    return render_template('decoder.html')

@app.route('/dnstools', methods=["GET", "POST"])
def dnstools():
    return render_template('dnstools.html')

@app.route('/hashingtools', methods=["GET", "POST"])
def hashingtools():
    return render_template('hashingtools.html')

@app.route('/mltools', methods=["GET", "POST"])
def mltools():
    return render_template('mltools.html')

"""
FORM PAGE SECTION
"""
@app.route('/urlDecoder', methods=["GET", "POST"])
def urlDecoderHome():
    if request.method == 'POST':
        response = request.form
        urlInput = response['urlDecoderURL']
        result = urlDecoder(urlInput)
        return render_template('result.html',HeadingToDisplay="Decoded URL",ResultToDisplay=result)
    return render_template('urlDecoder.html')

@app.route('/urlUnshortner', methods=["GET", "POST"])
def urlUnshortnerHome():
    if request.method == 'POST':
        response = request.form
        urlInput = response['urlUnshortnerURL']
        result = unshortenUrl(urlInput)
        return render_template('result.html',HeadingToDisplay="unShortened URL",ResultToDisplay=result)
    return render_template('urlUnshortner.html')

@app.route('/unfurlUrl', methods=["GET", "POST"])
def unfurlUrlHome():
    if request.method == 'POST':
        response = request.form
        urlInput = response['unfurlUrl']
        result = unfurlUrl(urlInput)
        print(result)
        result = Markup("<p>"+result.replace("\n","<br>")+"</p>")
        return render_template('result.html',HeadingToDisplay="unfurl Text Tree",ResultToDisplay=result)
    return render_template('unfurlUrl.html')

@app.route('/urlScan', methods=["GET", "POST"])
def urlScanHome():
    if request.method == 'POST':
        response = request.form
        urlInput = response['urlScan']
        type = response['type']
        heading,urlDisplay,overallVerdict,malicious,urlscanScore,fullreportLink = urlscanio(urlInput,type)
        # result = Markup("<p>"+result.replace("\n","<br>")+"</p>")
        return render_template('urlScan_result.html',HeadingToDisplay=Markup(heading),urlDisplay=Markup(urlDisplay),overallVerdict=Markup(overallVerdict),malicious=Markup(malicious),urlscanScore=Markup(urlscanScore),fullreportLink=Markup(fullreportLink))
    return render_template('urlScan.html')

@app.route('/urlSanitizer', methods=["GET", "POST"])
def urlSanitizerHome():
    if request.method == 'POST':
        response = request.form
        urlInput = response['urlSanitizerURL']
        result = urlSanitise(urlInput)
        return render_template('result.html',HeadingToDisplay="Sanitized URL",ResultToDisplay=result)
    return render_template('urlSanitizer.html')

@app.route('/safelinksDecoder', methods=["GET", "POST"])
def safelinksDecoderHome():
    if request.method == 'POST':
        response = request.form
        urlInput = response['safelinksDecoderURL']
        result = safelinksDecoder(urlInput)
        return render_template('result.html',HeadingToDisplay="SafeLinks Decoded URL",ResultToDisplay=result)
    return render_template('safelinksDecoder.html')

@app.route('/b64Decoder', methods=["GET", "POST"])
def b64DecoderHome():
    if request.method == 'POST':
        response = request.form
        urlInput = response['b64DecoderURL']
        result = b64Decoder(urlInput)
        return render_template('result.html',HeadingToDisplay="base64 Decoded URL",ResultToDisplay=result)
    return render_template('b64Decoder.html')

@app.route('/googleTranslator', methods=["GET", "POST"])
def googleTranslatorHome():
    if request.method == 'POST':
        response = request.form
        translatorInput = response['googleTranslatorText']
        heading,resultHTML = translateLanguage(translatorInput)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('googleTranslator.html')

@app.route('/pdfDetector', methods=["GET", "POST"])
def pdfDetectorHome():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            uploaded_file.save(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        heading,resultHTML = scanPDFFile(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        os.remove(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('pdfScanner.html')

@app.route('/reversednslookup', methods=["GET", "POST"])
def reversednslookupHome():
    if request.method == 'POST':
        response = request.form
        ip = response['reversednslookupText']
        heading,resultHTML = reverse_dns_lookup(ip)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('reversednslookup.html')

@app.route('/dnslookup', methods=["GET", "POST"])
def dnslookupHome():
    if request.method == 'POST':
        response = request.form
        domain = response['dnslookupText']
        heading,resultHTML = dnsLookup(domain)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('dnslookup.html')

@app.route('/whoislookup', methods=["GET", "POST"])
def whoislookupHome():
    if request.method == 'POST':
        response = request.form
        ip = response['whoislookupText']
        heading,resultHTML = whois_lookup(ip)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('whoislookup.html')

@app.route('/url_domain_analyzer', methods=["GET", "POST"])
def url_domain_analyzerHome():
    if request.method == 'POST':
        response = request.form
        domain = response['domain']
        heading,resultHTML = analyze_domain(domain)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('url_domain_analyzer.html')

@app.route('/url_url_analyzer', methods=["GET", "POST"])
def url_url_analyzerHome():
    if request.method == 'POST':
        response = request.form
        url = response['url']
        heading,resultHTML = analyze_url_ml(url)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('url_url_analyzer.html')

@app.route('/checkfile', methods=["GET", "POST"])
def check_file_hashHome():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            uploaded_file.save(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        heading,resultHTML = checkFileHash(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        os.remove(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('checkfile.html')

@app.route('/checkhash', methods=["GET", "POST"])
def checkhashHome():
    if request.method == 'POST':
        response = request.form
        hash = response['hash']
        heading,resultHTML = getHashReport(hash)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('checkhash.html')

@app.route('/reputationchecker', methods=["GET", "POST"])
def reputationcheckerHome():
    if request.method == 'POST':
        response = request.form
        rawInput = response['rawInput']
        print(rawInput)
        heading,resultHTML = repChecker(rawInput)
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('reputationchecker.html')

@app.route('/checkransomware', methods=["GET", "POST"])
def checkransomwareHome():
    if request.method == 'POST':
        uploaded_file = request.files['file']
        if uploaded_file.filename != '':
            uploaded_file.save(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        heading,resultHTML = checkransomware(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        os.remove(os.path.join(UPLOAD_FOLDER,uploaded_file.filename))
        return render_template('result.html',HeadingToDisplay=Markup(heading),ResultToDisplay=Markup(resultHTML))
    return render_template('checkransomware.html')

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
