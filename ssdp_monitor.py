#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Escucha paquetes SSDP en la red para 
# atender encendidos o apagados de equipos
# compatibles con UPnP
# 
# Lanza busquedas root-device
#
# Daniel Calvo
# Enero 2018
#
import socket
import struct
import datetime
import sys, os
import objetosHAB, restHAB
import argparse

CCuid = 'dc7ff7f0-a369-1366-c8dc-2693f16d3052'

Debug_Hablador  = True
Normal_Hablador = True

bbddObjetos = []

MCAST_GRP   = '239.255.255.250'
MCAST_PORT  = 1900
BUFFER_SIZE = 1024
ENCENDIDO   = "ssdp:alive"
APAGADO     = "ssdp:byebye"
MAX_TIEMPO  = 1800

OPENHAB     = '192.168.1.5'

valid_keys = (
        'M-SEARCH',
        'NOTIFY',
        'HOST',
        'SERVER',
        'NT',                  # Notification Type
        'NTS',                 # Notification Type Subtype
        'LOCATION',
        'CACHE-CONTROL',       # Atento, indica cuando va a morir
        'USN',                 # Unique service name
        'MX',
        'MAN',
        'ST',
        'USER-AGENT'           # OPT, EXT, DATE, 01-NLS, X-*, BOOTID.UPNP.ORG, CONFIGID.UPNP.ORG
)

keys_a_ignorar = ("01-NLS", "BOOTID.UPNP.ORG", "CACHE-CONTROL", "CONFIGID.UPNP.ORG", \
    "Content-Length", "DATE", "EXT", "HTTP/1.1 200 OK", "OPT", \
    "SERVER", "X-Accepts-Registration", "X-Friendly-Name", \
    "X-MDX-Caps", "X-MDX-ID", "X-MDX-Registered", "X-MSL", "X-User-Agent")

# Claves que leo cuando hago una búsqueda por root device
# adicionalmente me quedo con la clave UUID
# DATE, TIME, STATUS
#
keys_en_root = ("LOCATION", "SERVER", "ST", "USN", "CACHE-CONTROL", \
                "NT", "NTS")

DISCOVERY_MSG = ('M-SEARCH * HTTP/1.1\r\n' +
                 'ST: {}\r\n' +
                 'MX: 4\r\n' +
                 'MAN: "ssdp:discover"\r\n' +
                 'HOST: 239.255.255.250:1900\r\n\r\n')


def DebugHabla(*args):
    global ficheroAux

    if Debug_Hablador:
        print(*args, file = ficheroAux)
        ficheroAux.flush()
        os.fsync(ficheroAux.fileno())

def HablaPrint(*args):
    global ficheroSalida

    if Normal_Hablador:
        print(*args, file = ficheroSalida)


def DumpRegistro(ahoraTexto, registro):
    global ficheroSalida

    HablaPrint(ahoraTexto + "|", end = '')
    for item in registro:
        HablaPrint(item, registro[item], "|", end = '')
    HablaPrint("")

def LimpiarRegistrosAntiguos(bbdd, pulso):

    aBorrar = []
    for item in bbdd:
        if 'expira' in bbdd[item]:
            if (pulso-bbdd[item]['momento']).seconds > int(bbdd[item]['expira']):
                aBorrar.append(item)
                DebugHabla("He borrado un registro")
                DebugHabla(bbdd[item]['expira'])
        elif (pulso-bbdd[item]['momento']).seconds > MAX_TIEMPO:
            aBorrar.append(item)
            DebugHabla("He borrado un registro")
            DebugHabla(bbdd[item]['expira'])
    for item in aBorrar:
        del bbdd[item]
        #
        # Deberia actualizar el estado del objeto a apagado con REST
        # Pues he borrado el registro al no haber recibido actualización
        #


def ActualizarEstadoObjeto(uuid, registro):
    """
    Actualiza el estado de un objeto empleando REST
    El nuevo estado lo obtiene de registro
    Y el nombre del objeto, consultando en la bbdd por el uuid
    """
    global configuracionObjetos

    nombreObjeto = configuracionObjetos.BuscarUUID(uuid)
    if nombreObjeto == None:
        return

    # Averiguar el estado empleando REST
    objetoAPI = restHAB.ItemAPI()

    estadoREST = objetoAPI.GetStatus(nombreObjeto)
    if estadoREST == restHAB.ERROR:
        return
    
    estadoSSDP = registro['Status']

    if estadoREST == estadoSSDP:
        return
    else:
        objetoAPI.PutStatus(nombreObjeto, estadoSSDP)

def DescubrirRoot():
    """
    Hace una búsqueda de los dispositivos rootdevice
    que están activos y construye una base de datos con el contenido

    Devuelve como objeto la BBDD

    Solo interesa 
    DATE TIME
    FROM        UUID    Status
    LOCATION    ST      CACHE-CONTROL
    USN         SERVER  NT NTS
    """

# Cuando se hace una búsqueda con este comando, no devuelve la clave NT ni NTS

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

# Convierte a bytes la cadena de texto

    texto = DISCOVERY_MSG.format('upnp:rootdevice').encode()

    sock.sendto(texto, (MCAST_GRP, MCAST_PORT))

    sock.settimeout(1)

    bbdd = {}

    momentoInicial = datetime.datetime.today()

    ahora = datetime.datetime.today()

    while True:
        try:
            if (ahora - momentoInicial).seconds >= 4:
                break

            data, desde = sock.recvfrom(BUFFER_SIZE)
            
            data = data.split(b'\r\n')

            registro = {}

            registro['FROM'] = desde[0]

            ahora = datetime.datetime.today()
            registro['DATE'] = ahora.strftime("%d-%m-%Y")
            registro['TIME'] = ahora.strftime("%H:%M:%S")

            for item in data:
                linea = item.decode('utf-8')

                tokens = linea.split(":")

                if len(tokens) == 0 or tokens[0] == '':
                    continue

# Atención:
#   Aquí filtro las claves que voy a leer
                if tokens[0] not in keys_en_root:

# Puede tener sentido guardar las claves no reconocidas en un fichero para procesarlas

                    continue

# Almaceno la clave leida
                registro[tokens[0]] = (':'.join(tokens[1:])).strip()

# Ahora proceso un poco los comandos para tener un acceso más fácil
# a ciertas claves
                if tokens[0] == 'USN':
                    registro['UUID'] = tokens[2]
                    uuid = tokens[2]

                if tokens[0] == 'CACHE-CONTROL':
                    subtokens = tokens[1].split("=")
                    registro['CACHE-CONTROL'] = subtokens[1]

        except socket.timeout:
            tiempo = (datetime.datetime.today() - momentoInicial).seconds
            if tiempo >= 4:
                break
            continue
        
        registro['Status'] = 'ON'

        bbdd[uuid] = registro

#
# Convertir esto a algo opcional
#

    for item in bbdd:
        ActualizarEstadoObjeto(item, bbdd[item])
#        DumpRegistro(ahora.strftime("%d-%m-%Y %H:%M:%S"), bbdd[item])
            
    return bbdd

def BuscaRegistrosCaducados(bbdd):
    """
    Hace una búsqueda de registro que puedan estar caducados
    por ejemplo, por un fallo de corriente
    Actualiza su estado según la información que encuentre

    Modifica directamente la BBDD

    DATE TIME
    FROM        UUID    Status
    LOCATION    ST      CACHE-CONTROL
    USN         SERVER  NT NTS
    """
    
    ahora = datetime.datetime.today()

    for uuid, registro in bbdd.items():
        #
        # Primero comprobar si el registro está activo
        #
        if registro['Status'] == 'ON':
            tiempoAltaTexto = registro['DATE'] + ' ' + registro['TIME']
            tiempoAlta = datetime.datetime.strptime(tiempoAltaTexto, "%d-%m-%Y %H:%M:%S")
            diferencia = (ahora - tiempoAlta).seconds
            timeout    = int(registro['CACHE-CONTROL']) * 60
            if diferencia > timeout:
                # Poner a OFF el registro
                # Actualizar la bbdd
                registro['Status'] = 'OFF'
                
                ActualizarEstadoObjeto(uuid, registro)
    
        
    
def BuscaRegistroRoot(registro):
    """
    Hace una búsqueda de un registro en la base de datos global
    Solo busca dispositivos root en la clave NT
    Actualiza su estado según la información que encuentre

    Modifica directamente la BBDD

    DATE TIME
    FROM        UUID    Status
    LOCATION    ST      CACHE-CONTROL
    USN         SERVER  NT NTS
    """

    global bbddObjetos
    global ficheroSalida
    global ficheroAux


    if registro['NT'] != 'upnp:rootdevice':
        return

    DebugHabla(registro)

    uuid = registro['UUID']

    if uuid not in bbddObjetos:
        # Alta de un nuevo registro
        if registro['ACCION'] != 'ON':
            # Esta situación teóricamente no debería producirse
            # pero en la práctica, si
            # Por ejemplo, cuando el ChromeCast se enciende
            # empieza a enviar mensajes byebye
            # [FF02::C] (IPv6 link-local)
            # [FF05::C] (IPv6 site-local)
            # [FF08::C] (IPv6 organization-local)
            # [FF0E::C] (IPv6 global)
            # netsh int ipv6 show neigh
            # PowerShell Get-NetIPAddress
            registro['Status'] = 'OFF'
            bbddObjetos[uuid] = registro
            HablaPrint(registro['TIME'], registro['FROM'], uuid, "Apagando-2")
            ActualizarEstadoObjeto(uuid, registro)
        else:
            registro['Status'] = 'ON'
            bbddObjetos[uuid] = registro
            HablaPrint(registro['TIME'], registro['FROM'], uuid, "Encendiendo")
            ActualizarEstadoObjeto(uuid, registro)
            # Toca actualizar este objeto mediante REST
    else:
        antes = bbddObjetos[uuid]['Status']
        ahora = registro['ACCION']
        if antes != ahora:
            bbddObjetos[uuid]['Status'] = ahora
            if ahora == 'ON':
                HablaPrint(registro['TIME'], registro['FROM'], uuid, "Encendiendo")
            else:
                HablaPrint(registro['TIME'], registro['FROM'], uuid, "Apagando")
        else:
            HablaPrint(registro['TIME'], registro['FROM'], uuid, "Update", bbddObjetos[uuid]['TIME'])

        # Hay que pensar en varios casos:
        #   TV apagada sin avisar (quitando cable)
        #   Fallo de corriente
        #   Cambio de IP en medio de su funcionamiento
        # Por eso, actualizo algunos valores a continuación
        # Una alternativa sería un bucle recorriendo todos los campos buscando diferencias

        bbddObjetos[uuid]['FROM']   = registro['FROM']
        bbddObjetos[uuid]['DATE']   = registro['DATE']
        bbddObjetos[uuid]['TIME']   = registro['TIME']
        if 'CACHE-CONTROL' in registro:
            bbddObjetos[uuid]['CACHE-CONTROL'] = registro['CACHE-CONTROL']
        else:
            del bbddObjetos[uuid]['CACHE-CONTROL']
        
        ActualizarEstadoObjeto(uuid, bbddObjetos[uuid])
        

#
#
# Comienzo del bucle principal
# Hay algo distinto en los mensajes entre un update y una incorporación a la red??
#
#

parser = argparse.ArgumentParser()
parser.add_argument("-v",  nargs = '?', const='mio', default='no',
        help = 'Activa el modo Verbose, y opcionalmente indica el nombre del fichero a usar')
parser.add_argument("-d",  nargs = '?', const='mio', default='no',
        help = 'Activa el modo Debug, y opcionalmente indica el nombre del fichero a usar')

args = parser.parse_args()
if args.v == 'no':
    Normal_Hablador = False
else:
    Normal_Hablador = True
    if args.v == 'mio':
        ficheroSalida = sys.stdout
    else:
        ficheroSalida = open(args.v, 'w')

if args.d == 'no':
    Debug_Hablador = False
else:
    Debug_Hablador = True
    if args.d == 'mio':
        ficheroSalida = open("ssdp.out", 'w')
    else:
        ficheroSalida = open(args.d, "w")

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', MCAST_PORT))

mreq = struct.pack('=4s4s', socket.inet_aton(MCAST_GRP), socket.inet_aton(OPENHAB))   # pack MCAST_GRP correctly
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)                    # Request MCAST_GRP

configuracionObjetos = objetosHAB.Objetos()
objetos = configuracionObjetos.leer()


bbddObjetos = DescubrirRoot()

while True:
    respuesta, desde = sock.recvfrom(BUFFER_SIZE)
    respuesta = respuesta.split(b'\r\n')

    ahora = datetime.datetime.today()

    ahoraTexto = ahora.strftime("%d-%m-%Y %H:%M:%S")
    ahoraDia   = ahora.strftime("%d-%m-%Y")
    ahoraHora  = ahora.strftime("%H:%M:%S")

    paquete = {}

#
# Respuesta es una LISTA de objetos
#
    for linea in respuesta:
        linea = linea.decode('utf-8')

#        if linea.find('.55') != -1:
#            print("***", respuesta)
#
# No soy coherente pues cuando busco root, corto empleando ':'
# y aquí corto empleando el ' '
#
        tokens = linea.split()

        if len(tokens) == 0 or tokens[0] == '':
            continue

#
# Vuelvo a reconstruir la linea
#
        comando  = tokens[0]
        opciones = (' '.join(tokens[1:])).strip()
#
# linea es la linea entera
# tokens cada una de las palabras
# comando la primera palabra
# opciones el resto de las palabras de la linea
#        

# Voy construyendo paquete empleando como clave el comando recibido

        if comando[-1:] == ':':
            comando = comando[:-1]

        if comando in valid_keys:
            paquete[comando] = opciones
        elif comando not in keys_a_ignorar:
            paquete["Error " + comando] = opciones

# Acabó el for, en paquete debo tener el resultado

    if 'M-SEARCH' in paquete:
        tipo = 1
    elif 'NOTIFY' in paquete:
        tipo = 2
    else:
        DebugHabla(ahoraTexto, "ERROR: Comando recibido erroneo")
        DebugHabla(ahoraTexto, "ERROR: ", paquete)
        continue

# Aquí solo llego si el comando es uno de los dos aceptados

    host   = desde[0]
    puerto = desde[1]

    if tipo == 1:
#
# Entrada para tipo M-SEARCH
# No me interesan, así que vuelvo al bucle
#
        continue

#
# A partir de aqui, SOLO llego en el caso NOTIFY
#

    accion = ''

    if 'NTS' in paquete:
        if paquete['NTS'] == 'ssdp:alive':
            accion = "ON"
        elif paquete['NTS'] == 'ssdp:byebye':
            accion = "OFF"
    
    if accion == '':
        DebugHabla(ahoraTexto, "ERROR: NOTIFY desde: ", host)
        DebugHabla(ahoraTexto, "ERROR: ", paquete)
        continue

    #
    # Un poco de limpieza con el registro almacenado en paquete
    #
    if 'HOST' in paquete:
        del paquete['HOST']

    del paquete['NOTIFY']

    paquete['DATE']   = ahoraDia
    paquete['TIME']   = ahoraHora
    paquete['ACCION'] = accion
    paquete['FROM']   = host

    #
    # Dejo solo el tiempo en CACHE-CONTROL
    # para facilitar su uso
    #
    if 'CACHE-CONTROL' in paquete:
        subtokens = paquete['CACHE-CONTROL'].split("=")
        paquete['CACHE-CONTROL'] = subtokens[1]

    if 'USN' in paquete:
        subtokens = paquete['USN'].split(":")
        paquete['UUID'] = subtokens[1]

    BuscaRegistroRoot(paquete)
    BuscaRegistrosCaducados(bbddObjetos)

"""
-v mostrar informacion
-d mostrar informacion de debug

import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-v",  help="Mostrar mensajes de funcionamiento normal",
                    action="store_true")
parser.add_argument("-d",  help="Mostrar mensajes de debugging",
                    action="store_true")
                    
args = parser.parse_args()
print(type(args))
if args.v:
    print("verbosity turned on")
if args.d:
    print("Modo debugging ON")

"""