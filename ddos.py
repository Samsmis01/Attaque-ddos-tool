import requests
from termcolor import colored
import random
import time
import socket
import threading
from tests import detect_vulnerability, get_cookies, lfi_test, ddos_attack, bruteforce_attack_with_proxies, advanced_sql_injection_test,xss_attack

# Liste de proxies à utiliser
PROXY_LIST = ['http://proxy1', 'http://proxy2', 'http://proxy3']

def afficher_menu():
    print(colored("""
    ****************************************
    *        𝗕𝗜𝗘𝗡𝗩𝗘𝗡𝗨𝗘 𝗦𝗨𝗥 𝗛𝗘𝗫♥︎𝗧𝗘𝗖𝗛  ⚕️  *
    ****************************************
    """, "blue"))
    print(colored("""
    ****************************************
    *          𝙷𝙴𝚇✦𝚃𝙴𝙲𝙷                   ✦
    *  ＰＩＲＡＴＡＧＥ ＤＥＳ ＳＩＴＥ ＷＥＢ   ✦
    *
    * 1. Entrer l'URL du site cible        *
    * 2. Rejoindre notre canal Telegram    *
    * 3. Effectuer une attaque XSS         *
    * 4. Effectuer une attaque CSRF        *
    * 5. Effectuer un fuzzing              *
    ****************************************
    """, "green", attrs=["bold", "underline"]))  # Menu en vert et stylisé

def main():
    afficher_menu()
    choix = input(colored("Choisissez une option (1, 2, 3, 4, 5) : ", "green"))
    
    if choix == "1":
        url = input("Entrez l'URL du site cible : ")
        print(f"Analyse en cours sur {url}...\n")
        run_tests(url)
    elif choix == "2":
        print("Redirection vers le canal Telegram...")
        import os
        os.system("xdg-open https://t.me/+IcftRA7eTCNiOGFk?start=7699384839")
    elif choix == "3":
        url = input("Entrez l'URL du site cible : ")
        print(f"Lancement de l'attaque XSS sur {url}...\n")
        xss_attack(url)
    elif choix == "4":
        url = input("Entrez l'URL du site cible : ")
        print(f"Lancement de l'attaque CSRF sur {url}...\n")
        csrf_attack(url)
    elif choix == "5":
        url = input("Entrez l'URL du site cible : ")
        print(f"Lancement du fuzzing sur {url}...\n")
        fuzzing_attack(url)
    else:
        print(colored("Option invalide. Veuillez réessayer.", "red"))
        main()

def run_tests(url):
    print(colored("[DANGER⚠️ ⚠️] Début de l'injection ...", "cyan"))

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

    # Délai de 10 secondes pour l'attaque bruteforce
    print(colored("[*] Attente de 10 secondes avant de commencer l'attaque brute force...", "yellow"))
    time.sleep(10)  # Délai de 10 secondes

    # Test de bruteforce avec proxy (Exécuté en dernier)
    print(colored("[*] Démarrage de l'attaque brute force...", "yellow"))
    bruteforce_result = bruteforce_attack_with_proxies(url, chars="ab", max_length=3)
    if bruteforce_result:
        print(colored(f"[+] Bruteforce réussi avec : {bruteforce_result}", "green"))
    else:
        print(colored("[-] Bruteforce échoué.", "red"))

    print(colored("[*] Tests terminés.", "cyan"))

def xss_attack(url):
    print(colored("[WARNING ⚠️] Lancement de l'attaque XSS...", "yellow"))
    # Ajouter ici l'implémentation de l'attaque XSS
    pass  # Remplacer par le code de l'attaque XSS

def csrf_attack(url):
    print(colored("[DANGER ☣️] Lancement de l'attaque CSRF...", "yellow"))
    # Ajouter ici l'implémentation de l'attaque CSRF
    pass  # Remplacer par le code de l'attaque CSRF

def fuzzing_attack(url):
    print(colored("[ATTENTION 🦠] Lancement du fuzzing...", "yellow"))
    # Ajouter ici l'implémentation du fuzzing
    pass  # Remplacer par le code du fuzzing

if __name__ == "__main__":
    main()
