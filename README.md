# RSA : messages stéréotypés

Le responsable informatique de la société CryptoFlop est un homme avisé :
il change régulièrement les mots de passe des employés, transmettant
à chacun son nouvel identifiant par simple mail de la forme::

  "Cher collaborateur, votre nouveau mot de passe est xxxxxxxxxx. Merci de votre comprehension, le service informatique."

mais en prenant soin de sécuriser le corps du mail par un chiffrement RSA
avec la clef publique du destinataire.

Le fichier ``main.gp`` contient les scripts qu'il utilise.

Etudiez l'aide de la fonction ``zncoppersmith`` de Pari/GP, et déterminez le
mot de passe correspondant au corps de mail intercepté dans le fichier
``input.txt``.

La première ligne est la clef publique ``[n,e]`` et
la seconde le chiffré. Affichez tout le message déchiffré.

## Format

Vous devez écrire un programme `main.gp` en Pari/GP dont l'exécution via
```
gp -fq < main.gp
```
affiche (uniquement) la solution cherchée.

taper `make check` permet de vérifier que votre solution est bonne.

Veillez à mettre des commentaires sur votre démarche et sa validité
dans le fichier ``main.gp``.

De manière alternative, vous pouvez écrire un programme `main.c` qui
fasse la même chose.

## Validation

Il reste à faire un commit et à envoyer votre solution pour l'enregistrer
```
git add main.gp
git commit -m 'ma solution'
git push
```

