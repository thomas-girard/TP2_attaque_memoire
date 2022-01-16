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

* On commence par les instructions classiques jump/call/pop qui permettent d’écrire l’adresse de la chaîne de caractères */bin/sh* dans le registre ebp (cette adresse sera utiliée par la suite au moment de l’appel système execve).
* On a ensuite une remise à 0 d’une partie des registres.
* On remarque ensuite un appel à *mmap2*, sûrement pour se réserver un segment en mémoire avec des permissions particulières.
* On a ensuite ce qui semble être un boucle for avec un appel système à *getppeername* afin probablement d’attacher le shell à la socket utilisée par l’attaquant.
* Enfin, on trouve bien l’appel système à *execve* avec la chaîne de caractère "/bin/sh" en paramètre afin de lancer le shell.


# Faille n° 1 : format string


# Faille n° 2 : buffer overflow

Après avoir récupéré une adresse de la stack grâce à la faille n°1 *format string*, l’attaquant a utilisé une deuxième faille dans le code C afin de pouvoir réaliser un buffer overflow. 

Afin d’éviter justement les buffer overflows, les développeurs ont choisi de créer une fonction *sanitizeBuffer* qui permet de copier l’entrée utilisateur contenue dans *unsafeBuffer* dans un buffer limité à 200 caractères *safeBuffer* et en stoppant la copie au premier au premier caractère non-imprimable trouvé. Cependant, les développeurs se sont trompés dans l’écriture de leur code ce qui permet a permis à l’attaquant d’écrire plus de 200 caractères. 
En effet, si l’attaquant rentre exactement 200 caractères suivis d’un retour à la ligne \n, alors le code C va réaliser les actions suivantes :
* remplacement du \n (0a en hexadécimal) par \0
* calcul de strlen(unsafeBuffer), ici le résultat de ce calcul donne 200
* copie caractère par caractère de *unsafeBuffer* dans *safeBuffer* de l’indice 0 à l’indice 201 ! (cf capture d’écran ci-dessous) Un caractère de trop a donc été copié et donc l’attaquant peut déborder de *safeBuffer*. Ce caractère copié en trop est forcément un 0 (car le \n a été remplacé précédemment par \0 et est copié dans la mémoire après *safeBuffer*.

![faille_sanitizeBuffer](/images/faille_sanitizeBuffer.png)
*extrait du code C de la fonction incriminée sanitizeBuffer*



# Conclusion
