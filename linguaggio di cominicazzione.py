
symbols = {
    'A': '.',
    'B': '..',
    'C': '-',
    'D': '#',
    'E': '@',
    'F': '[',
    'G': '!',
    'H': '$',
    'I': '+',
    'J': '(',
    'K': '^',
    'L': ':',
    'M': '?',
    'N': ']',
    'O': '<',
    'P': '>',
    'Q': '%',
    'R': '£',
    'S': '=',
    'T': '/',
    'V': '\\',
    'W': ';',
    'X': '°',
    'Y': 'ç',
    'Z': '&',
}

word = input("Inserisci una parola: ").upper()
translated_word = ""

for letter in word:
    if letter in symbols:
        translated_word += symbols[letter]
    else:
        translated_word += letter

print(f"La parola '{word}' tradotta è '{translated_word}'.")
