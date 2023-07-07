# Hook-v2 🇫🇷

<img src="https://www.emojimeaning.com/img/img-twitter-64/1f1eb-1f1f7.png" width="25" height="25">

> Hook-v2 est un projet qui permet de créer des hooks en utilisant AsmJit pour intercepter des appels de fonctions. 
Il permet de restaurer automatiquement la pile, les registres (x64 et x86) et les flags du processeur pour passer inaperçu. 
Les hooks sont dotés d'une structure qui permet de les attacher ou de les détacher, de modifier l'adresse de callback, de verrouiller & déverrouiller la région mémoire (non recommandé), de les renommer et de les détruire.

> Il y a un store global appelé HookStore qui stocke les hooks, ce qui vous permet d'y accéder n'importe où dans votre code. 
Il y a également une page globale pour tous les hooks, ce qui signifie que les hooks seront placés sur une page de taille (x*128) où x est le nombre de hooks. 
Par défaut, x est de 32, donc la taille de la page est de 4096 (taille par défaut d'une page sur Windows 10). 
La destruction d'un hook est gérée par la fonction "Destroy" qui gère l'alignement des hooks dans la mémoire pour éviter les trous d'octets et ainsi économiser de l'espace.

> Un callback reçoit la structure du hook auquel il est attaché ainsi qu'une structure de registres, ce qui permet de modifier directement les registres et de détacher le hook si nécessaire. 
Il est également possible d'attacher plusieurs fonctions avec le même callback.


#### ⚠️ Note: vous devez indiquer les octets a "voler", pour une application x64, le nombre d'octet est de 13 et sur x86 il est de 5.

#### ❗  Comme le deuxième argument est directement la pile, certaines fonctions écraseront les arguments, donc la pile. Par exemple, std::cout le fait, tandis que printf ne le fait pas. 

#### ❗ Certaines opérations asynchrones ne sont pas prises en compte pour l'instant, telles que OutputDebugString. Bien que cette fonction soit censée être synchrone, elle a des sous-couches asynchrones qui peuvent écraser la pile.

<br />

> #### ♠️ AsmJit : https://github.com/asmjit/asmjit

<br />

![](https://img.shields.io/static/v1?label=Langage&message=Cpp&color=blue)

### POC (x64) :
![](https://github.com/Sx-Cheats/Hook-v2/blob/main/Previews/1.PNG)

Dans cet exemple, nous accrochons la fonction "MessageBoxTimeoutA" en utilisant le callback "ffghfgf" et en précisant qu'il nécessite 13 bytes d'espace mémoire. 
Nous nommons ce hook "Hook MessageBoxA". 
Ensuite, nous affichons l'adresse de base de notre hook dans la console.

Le premier appel à "MessageBoxA" sera accroché par défaut, mais vous pouvez l'éviter en spécifiant false comme dernier argument de la fonction Hook. 
Le titre du message box (trait vert) est situé dans le registre r8 (trait jaune), et nous forcons la modification avec la fonction WriteWordChar (trait rouge). Enfin, nous détachons le hook.

![](https://github.com/Sx-Cheats/Hook-v2/blob/main/Previews/2.PNG)

Nous avons détaché notre hook pendant que le callback était appelé (trait jaune), ainsi la fonction MessageBoxTimeoutA retrouve son état normal, et notre titre également (trait vert).

J'espère que ce petit projet vous plaira, n'hésitez pas à le star ou le fork 😉.

![](https://img.shields.io/static/v1?label=Discord&message=$x%232170&color=blue)
