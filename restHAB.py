#!/usr/bin/python
#
# Comunicaciones REST con openHAB para actualizar
# el estado de diferentes items
#
# Daniel Calvo
# Enero 2018
#
""" 
Comunicación REST con openHAB\n
Implementa clase ItemAPI
"""
import requests

ERROR = 'ERROR'

#
# Obtiene el estado de un item
#

URL = 'http://192.168.1.5:8080/rest/items/'
URL_CATEGORIA = '/state'

class ItemAPI(object):
    def __init__(self, url = URL, urlCategoria = URL_CATEGORIA):
        self.url = url
        self.urlCategoria = urlCategoria

    def setup(self, url = URL, urlCategoria = URL_CATEGORIA):
        self.url = url
        self.urlCategoria = urlCategoria

    def GetStatus(self, objeto):
        """
        Obtiene el estado de un objeto via REST
        Que lo devuelve como resultado de la función.
        En caso de error, devuelve el literal restHAB.ERROR
        """

        camino = self.url + objeto + self.urlCategoria
        respuesta = requests.get(camino)
        if respuesta.status_code != 200:
            return ERROR
        else:
            return respuesta.text

    def PutStatus(self, objeto, estado):
        """
        Cambia el estado de un objeto via REST

        Si tiene éxito devuelve OK, 
        en caso contrario, devuelve restHAP.ERROR
        """

        camino = self.url + objeto + self.urlCategoria
        respuesta = requests.put(camino, data=estado)
#        Debug(LOG_DEBUG, "Objeto " + objeto)
#        Debug(LOG_DEBUG, "Estado " + estado)
    #   202	Accepted
    #   400	Item state null
    #   404	Item not found
        if respuesta.status_code != 202:
 #           Debug(LOG_DEBUG, "No existente")
            return ERROR
        else:
            return "OK"
