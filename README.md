ssdp_openhab
============

[![Build Releases](https://img.shields.io/github/release/danielcalvogonzalez/ssdp_openhab.svg)](https://github.com/danielcalvogonzalez/ssdp_openhab/releases)

Monitoriza objetos en la red local, empleando como protocolo **ssdp** y sincroniza (y reporta) su estado con la plataforma **openHAB**.

¿Qué es?
--------
Monitoriza objetos que soporten el protocolo ssdp y actualiza su estado convenientemente en la plataforma openHAB, empleando el protocolo REST.

¿Cómo funciona?
----------------
Debemos declarar los objetos a monitorizar en un fichero de configuración `/etc/openhab2/ssdp/objetos.cfg`, indicado su UUID uPnP junto al nombre del objeto en openHAB. El programa se basa en el uso del UUID, pues asume que el objeto puede emplear DHCP para obtener su dirección IP, por lo que ésta podría cambiar entre una sesión y otra.

¿Qué necesitas?
---------------
Una instalación corriendo [openHAB] (http://openhab.org), tipicamente, una Raspberry PI, sobre la que sse puede ejecutar este programa.
Python 3, que es la versión utilizada para el desarrollo.

Estado del proyecto
-------------------
No se puede considerar a este proyecto como completo en el momento actual. Corresponde más bien, a un ejercicio del autor para desarrollar código en Python que pueda ser útil y expandible a otros usos.

En el futuro
------------
Actualmente, solo funciona sobre IP v4 y no sobre IP v6.
Los equipos **Chromecast** no emplean SSDP de forma habitual sobre IP v4, por lo que no pueden ser monitorizados.
Añadir un registro de todos los objetos que se descubran a lo largo del funcionamiento del programa, y así poder conocer todo lo que tengas en casa que soporte SSDP.

