# Conditions d'utilisation éthique et clause de non-responsabilité

Ce fichier complète la licence MIT : il définit les usages autorisés et
interdits du logiciel, et dégage la responsabilité des auteurs.

## Usage autorisé uniquement

Ce logiciel est un **outil de test de sécurité professionnel**. Il ne doit
être utilisé que :

- sur des systèmes **dont vous êtes propriétaire** ;
- sur des systèmes pour lesquels vous détenez une **autorisation écrite
  préalable** du propriétaire (mandat de pentest, contrat de prestation,
  programme de bug bounty dont le périmètre couvre la cible) ;
- dans un cadre légal (audit interne, conformité NIS2 / ISO 27001 / DORA,
  environnements d'entraînement comme TryHackMe, OWASP Juice Shop).

Le mécanisme de vérification de cible intégré (token
`/.well-known/ptaas-verify.txt` ou validation admin avec référence
d'autorisation écrite) existe pour matérialiser cette autorisation ; le
contourner annule toute utilisation légitime du logiciel.

## Usages interdits

Sont expressément interdits :

- tout scan, test d'intrusion ou tentative d'exploitation sur un système
  tiers sans autorisation écrite ;
- toute utilisation visant à nuire, voler des données, perturber ou
  compromettre un service ;
- toute utilisation en violation des lois applicables (en France :
  articles 323-1 et suivants du Code pénal ; au Cameroun : loi 2010/012
  sur la cybersécurité ; dans l'UE : directive NIS2 et droit pénal local).

## Responsabilité

L'utilisateur final est **seul responsable** de son usage du logiciel et
de l'obtention des autorisations nécessaires. Les auteurs et
contributeurs **n'acceptent aucune responsabilité** pour les dommages,
pertes, conséquences juridiques ou préjudices résultant d'une
utilisation illégale, non autorisée ou inappropriée du logiciel.

Le logiciel est fourni « tel quel », sans garantie. Rien dans ce document
ne constitue un conseil juridique : faites valider votre cadre
contractuel (CGU, mandats, assurance RC Pro) par un professionnel du
droit avant toute exploitation commerciale.
