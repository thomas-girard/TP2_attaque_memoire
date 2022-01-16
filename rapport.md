% Réponse à incident /  Exploitation d’une vulnérabilité dans un serveur TCP/IP programmé en langage C
% Olivier Nachin & Thomas Girard
% 17/01/22

# Introduction

# Analyse Réseaux

# Analyse de la payload
## Décomposition de la payload

Grâce à la trace réseau, nous avons donc pu récupérer la payload utilisée par l’attaquant. 

![payload_hexdump](/images/payload_hexdump.png)
*hexdump de la payload utilisée par l’attaquant*

* La payload commence par 64 octets de valeur "90", ce qui correspond au *toboggan de NOP*. L’attaquant souhaite que le fil d’exécution du programme du serveur arrive dans ce toboggan afin de sauter de NOP en NOP jusqu’au code permettant d’obtenir le shell.
* Ensuite, la payload continue avec 127 octets correspondant au code permettant d’obtenir un shell (nous allons détailler cette partie dans la suite).
* Puis, un padding de 9 "A" est ajouté afin d’obtenir exactement 200 octets depuis le début de la payload (de même, nous allons expliquer pourquoi il est important d’obtenir 200 octets exactement à cet endroit de la payload).
* Il y a ensuite 14 octets restants dont nous allons détailler le rôle par la suite.

## Analyse du code assembleur permettant d’obtenir un shell

Afin d’analyser la façon dont l’attaquant a réussi à ouvrir le shell, on désassemble le code permettant de l’obtenir. 

![code_assembleur](/images/extrait_assembleur.png)
*extrait du code assembleur permettant d’obtenir le shell*

* On commenc


# Faille n° 1

# Faille n° 2

# Conclusion
