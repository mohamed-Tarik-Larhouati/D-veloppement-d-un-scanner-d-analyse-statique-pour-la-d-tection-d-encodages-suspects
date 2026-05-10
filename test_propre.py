# ==========================================
# TEST : FICHIER PROPRE (score cible = 0)
# ==========================================
# Script Python sans mot-clé ni encodage suspect.
# Tous les tokens font moins de 12 caractères.

def add(a, b):
    return a + b

def sub(a, b):
    return a - b

def mul(a, b):
    return a * b

def div(a, b):
    if b == 0:
        raise ValueError("Zéro interdit.")
    return a / b

def show(op, val):
    print(f"Op={op} : {val}")

def main():
    x, y = 42, 7
    show("+", add(x, y))
    show("-", sub(x, y))
    show("*", mul(x, y))
    show("/", div(x, y))

if __name__ == "__main__":
    main()
