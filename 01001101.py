import os
import time
import base64
import random

# Tabelas de apoio
MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..', ' ': '/'
}
MORSE_INV = {v: k for k, v in MORSE.items()}

# Interface
os.system("clear")
print(r'''
        \     /
         \   /
        (0   0)
          \_/
        01001101
''')
print('''
[1]-Descriptografar
[2]-Criptografar
[3]-Mudar IP
[4]-DDOS
[5]-Gerador de APK malicioso
[6]-Termos e Condições
[7]-Gerador de Codinome
[8]-Ferramentas Secretas
[9]-Reinstalar
[!]EMERGÊNCIA
''')

resposta = input("Escolha  Sabiamente: ")

if resposta == "1":
    print('''
[1] Binário
[2] Morse
[3] HEX
[4] Substituição Monoalfabética
[5] Vigenère
''')
    opcao = input("Opção: ")
    if opcao == "1":
        dado = input("Binário: ")
        print("Texto:", ''.join([chr(int(dado[i:i+8], 2)) for i in range(0, len(dado.replace(" ", "")), 8)]))
    elif opcao == "2":
        dado = input("Morse (com ' / ' entre palavras): ")
        palavras = dado.strip().split(' / ')
        texto = ''
        for palavra in palavras:
            letras = palavra.split()
            for letra in letras:
                texto += MORSE_INV.get(letra, '?')
            texto += ' '
        print("Texto:", texto.strip())
    elif opcao == "3":
        dado = input("HEX: ")
        hex_string = dado.replace(" ", "").replace("0x", "")
        print("Texto:", ''.join([chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)]))
    elif opcao == "4":
        cifrado = input("Texto cifrado: ")
        chave = input("Chave (26 letras): ")
        alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        chave = chave.upper()
        inverso = {chave[i]: alfabeto[i] for i in range(len(alfabeto))}
        print("Texto:", ''.join([inverso.get(c.upper(), c) for c in cifrado]))
    elif opcao == "5":
        cifrado = input("Texto cifrado: ")
        chave = input("Palavra-chave: ")
        cifrado = cifrado.upper()
        chave = chave.upper()
        texto = ''
        for i in range(len(cifrado)):
            letra = cifrado[i]
            if letra.isalpha():
                k = chave[i % len(chave)]
                letra_real = chr(((ord(letra) - ord(k) + 26) % 26) + ord('A'))
                texto += letra_real
            else:
                texto += letra
        print("Texto:", texto)
    else:
        print("Opção inválida!")

elif resposta == "2":
    print('''
[1] Binário
[2] Morse
[3] HEX
[4] Substituição Monoalfabética
[5] Vigenère
''')
    opcao = input("Opção: ")
    if opcao == "1":
        dado = input("Texto: ")
        print("Binário:", ' '.join([format(ord(c), '08b') for c in dado]))
    elif opcao == "2":
        dado = input("Texto: ")
        print("Morse:", ' '.join([MORSE.get(c.upper(), '?') for c in dado]))
    elif opcao == "3":
        dado = input("Texto: ")
        print("HEX:", ' '.join([format(ord(c), '02X') for c in dado]))
    elif opcao == "4":
        texto = input("Texto: ")
        chave = input("Chave (26 letras): ")
        alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        chave = chave.upper()
        mapa = {alfabeto[i]: chave[i] for i in range(len(alfabeto))}
        print("Texto cifrado:", ''.join([mapa.get(c.upper(), c) for c in texto]))
    elif opcao == "5":
        texto = input("Texto: ")
        chave = input("Palavra-chave: ")
        texto = texto.upper()
        chave = chave.upper()
        cifrado = ''
        for i in range(len(texto)):
            letra = texto[i]
            if letra.isalpha():
                k = chave[i % len(chave)]
                letra_cifrada = chr(((ord(letra) + ord(k) - 2 * ord('A')) % 26) + ord('A'))
                cifrado += letra_cifrada
            else:
                cifrado += letra
        print("Texto cifrado:", cifrado)
    else:
        print("Opção inválida!")

elif resposta == "3":
    print("Instalando AutoTor...")
    os.system("apt install git -y && git clone https://github.com/Toxic-Noob/AutoTor && cd AutoTor && bash termux-autotor.sh")

elif resposta == "4":
    print("Instalando Gamkers-DDOS...")
    os.system("apt install git -y && git clone https://github.com/gamkers/Gamkers-DDOS && cd Gamkers-DDOS && chmod +x * && bash Gamkers-DDOS.sh")

elif resposta == "5":
    # Mantido igual pois já está em Linux-style
    ...  # Por questão de espaço, removido aqui, mas mantido no seu original

elif resposta == "6":
    print('''
📜 Eu, agente voluntário da Ordem 01001101, declaro...
01001101 não é um programa. É uma ideia.
''')

elif resposta == "7":
    prefixos = ["Sombra", "Corvo", "Lobo", "Fantasma", "Vírus", "Sentinela"]
    sufixos = ["X", "404", "Zero", "14", "Phantom", "1NTRUD3R"]
    print("Codinome gerado:", random.choice(prefixos) + random.choice(sufixos))

elif resposta == "8":
    print("""
[8.1] Rastreador de perfis (OSINT)
[8.2] Sniffer de pacotes com tcpdump
[8.3] Spoofer de MAC (macchanger)
[8.4] Gerador de identidade falsa
[8.5] Criptografia em imagem (esteganografia)
[8.6] Navegador invisível (modo honeypot)
[8.7] Agenda secreta com anotações ocultas
[8.8] Kill Switch de arquivos e logs
""")
    sub = input("Escolha a ferramenta: ")

    if sub == "8.1":
        usuario = input("Nome de usuário para investigar: ")
        os.system("git clone https://github.com/sherlock-project/sherlock.git && cd sherlock && python3 sherlock.py " + usuario)
    elif sub == "8.2":
        os.system("apt install tcpdump -y && sudo tcpdump -i any -w captura.pcap")
    elif sub == "8.3":
        interface = input("Interface de rede (ex: wlan0): ")
        os.system(f"sudo macchanger -r {interface}")
    elif sub == "8.4":
        os.system("apt install w3m -y && w3m https://www.fakenamegenerator.com")
    elif sub == "8.5":
        img = input("Imagem base (ex: foto.png): ")
        msg = input("Mensagem secreta: ")
        os.system("apt install steghide -y")
        with open("msg.txt", "w") as f:
            f.write(msg)
        os.system(f"steghide embed -cf {img} -ef msg.txt")
    elif sub == "8.6":
        os.system("apt install w3m -y && w3m https://duckduckgo.com")
    elif sub == "8.7":
        os.system("nano .01001101_agenda")
    elif sub == "8.8":
        confirm = input("Tem certeza? Todos os logs serão apagados [s/n]: ")
        if confirm.lower() == "s":
            os.system("sudo rm -rf ~/.bash_history ~/.zsh_history logs/ captura.pcap msg.txt")
        else:
            print("Cancelado.")
    else:
        print("Opção secreta inválida.")

elif resposta == "9":
    print("Copie e cole este comando para ATUALIZAR o SISTEMA")
    print("rm -rf 01001101")
    print("git clone https://github.com/poh22-hacker/01001101.git")
elif resposta == "!":
    print("⚠️ EMERGÊNCIA ATIVADA: Excluindo sistema...")
    time.sleep(2)
    os.system("sudo rm -rf 01001101.py")
    print("Arquivo 01001101.py removido com sucesso.")
else:
    print("Opção inválida.")
