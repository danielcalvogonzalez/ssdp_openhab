ssdp_openhab
============

Monitoriza objetos en la red local, empleando como protocolo ssdp y sincroniza (y reporta) su estado con la plataforma openHAB.

¿Qué es?
--------
Monitoriza objetos que se puedan comunicar con ssdp y actualiza su estado convenientemente en la plataforma openHAB, empleando el protocolo REST.

¿Cómo funciona?
----------------
Debemos declarar los objetos a monitorizar en un fichero de configuración `/etc/openhab2/ssdp/objetos.cfg`, indicado su UUID uPnP junto al nombre del objeto en openHAB. El programa se basa en el uso del UUID, pues asume que el objeto pueda emplear DHCP para obtener su dirección IP, por lo que ésta podría cambiar entre una sesión y otra.

¿Qué necesitas?
---------------

Estado del proyecto
-------------------
No se puede considerar a este proyecto como completo en el momento actual. Corresponde más bien, a un ejercicio del autor para desarrollar código en Python que pueda ser útil y expandible a otros usos.

