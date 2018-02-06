#!/usr/bin/python
#
# Lee el fichero de configuración entre objetos y uuid
# para openHAB
#
# Daniel Calvo
# Enero 2018
#
import os, sys

NOM_PATH_CONFIG = "/etc/openhab2/ssdp/"
NOM_FICHERO_CONFIG = "objetos.cfg"

NO_PATH = 1
NO_FICHERO = 2
CONFIG_ERRONEA = 3

#
# El fichero está compuesto por
#
# UUID   Nombre
#
#
class Objetos(object):
    def __init__(self, pathObjetos = ""):
#
# SI pathObjetos tiene un /, se asume que es un path completo
# Si no aparece /, se asume que es un fichero
#
        if len(pathObjetos) != 0 and pathObjetos.find("/") != 0:
            self.filename = pathObjetos
        else:
            try:
                path = os.environ['OPENHAB_CONF'] + "/ssdp/" 
            except KeyError:
                path = "/etc/openhab2/ssdp/"
            if pathObjetos == "":
                self.filename = path + NOM_FICHERO_CONFIG
            else:
                self.filename = path + pathObjetos
        self.listaObjetos = {}

    def __ErrorFatal(self, codigo, nombre):
        print(__name__ + ':', "ERROR FATAL: Fichero {0} no existe o no es accesible".format(nombre))
        exit(codigo)

    def BuscarUUID(self, uuid):
        if self.listaObjetos == {}:
            return None

        if uuid in self.listaObjetos:
            return(self.listaObjetos[uuid])
        else:
            return None

    def leer(self):

        try:
            handle = open(self.filename, "r")
        except FileNotFoundError:
            self.__ErrorFatal(NO_FICHERO, self.filename)
        
        self.listaObjetos = {}

        for linea in handle:
            linea = linea.strip()

            if linea.startswith("#"):
                continue

            tokens = linea.split()

            if len(tokens) == 0:
                continue

            if len(tokens) != 2:
                print(__name__ + ':', "ERROR: contenido del fichero de configuración erroneo", \
                    file=sys.stderr)
                print(__name__ + ':', "ERROR: encontrada línea con {0} argumentos".format(len(tokens)), \
                    file=sys.stderr)

            self.listaObjetos[tokens[0]] = tokens[1]
        
        handle.close()
        
        return self.listaObjetos
