# LEARN — AppSec, DevSecOps et préparation entretien

Ce fichier explique, en français simple, tout ce qu'il faut comprendre pour **défendre ce
projet en entretien** : ce que fait chaque outil, comment il se trompe, pourquoi les tests
existent, et ce qu'il ne faut jamais prétendre. Lis-le à voix haute au moins une fois.

---

## 1. Le projet en deux minutes

J'ai construit un petit portail de commandes pour AgriSouss, une PME fictive d'Agadir qui
vend de l'huile d'argan et du safran. Un client voit ses commandes, ajoute une note de
livraison et exporte en CSV ; le personnel voit tout et change le statut.

Le portail est **sécurisé dès la conception** : SQL paramétré, contrôle d'accès par objet,
jeton CSRF, en-têtes de sécurité, cookies durcis, mots de passe hachés, limitation des
tentatives de connexion. **78 tests** prouvent que ces protections tiennent, et un script de
**mutation** enlève chaque protection une à une pour vérifier qu'un test casse (16/16).

Autour, un **pipeline GitHub Actions** lance six familles d'outils open source (Semgrep,
Bandit, Gitleaks, pip-audit, Trivy, OWASP ZAP) et **bloque le build** sur un problème grave.
J'ai écrit **7 règles Semgrep maison**, chacune testée avec des exemples qui doivent
déclencher et d'autres qui ne doivent pas déclencher.

---

## 2. SAST, DAST, SCA, secrets : quelle différence ?

| Famille | Ce qu'elle regarde | Quand | Outil ici | Elle trouve | Elle rate |
|---|---|---|---|---|---|
| **SAST** (Static Application Security Testing) | le **code source**, sans l'exécuter | à chaque commit | Semgrep, Bandit | SQL formaté, `debug=True`, `verify=False`, route sans décorateur | tout ce qui dépend des données ou de la logique métier (IDOR) |
| **DAST** (Dynamic AST) | l'**application qui tourne**, de l'extérieur, par HTTP | après build | OWASP ZAP | en-têtes manquants, cookies sans flags, fuite de version, erreurs | le code qu'il ne voit pas (pages derrière login si non authentifié) |
| **SCA** (Software Composition Analysis) | les **dépendances** et leurs versions | à chaque commit + chaque semaine | pip-audit, Trivy | une CVE publiée dans Werkzeug, un paquet Debian vulnérable | les failles pas encore publiées, ton propre code |
| **Secret scanning** | le texte de **tout l'historique git** | à chaque commit | Gitleaks (+ Trivy) | clés API, mots de passe, clés privées au format connu | un secret au format inconnu ou découpé |
| **Misconfig / IaC** | Dockerfile, fichiers de config | à chaque commit | Trivy (misconfig) | conteneur en root, pas de `USER` | ce qui n'est pas dans un fichier |
| **Tests de sécurité unitaires** | le comportement réel des contrôles | à chaque commit | pytest | IDOR, CSRF, throttling, échappement | ce à quoi personne n'a pensé |

**Phrase à retenir :** aucun outil ne suffit seul. Le SAST voit le code mais pas l'exécution,
le DAST voit l'exécution mais pas le code, le SCA voit les autres mais pas toi, et aucun ne
comprend la logique métier : c'est pour ça qu'il y a des tests écrits à la main.

---

## 3. Comment marche chaque outil

### Semgrep (SAST)
- Il transforme le code en **arbre syntaxique** (AST), puis cherche des **motifs** qui
  ressemblent à du code : `$C.execute(f"...", ...)` trouve tout `execute` appelé avec une
  f-string, quel que soit le nom de la variable. `$C` est une **métavariable**.
- `pattern-not` exclut les cas sûrs, `pattern-inside` limite le contexte,
  `metavariable-regex` filtre un nom.
- **Mode taint** (règle `flask-render-template-string-user-input`) : on déclare des
  **sources** (`request.args`, `request.form`) et des **puits** (`render_template_string`).
  Semgrep suit la donnée de la source au puits à l'intérieur d'une fonction.
- `p/owasp-top-ten` et `p/python` sont des paquets de règles du registre Semgrep.
- **Tester une règle** : à côté de `rules/x.yaml`, le fichier `rules/x.py` contient des lignes
  annotées `# ruleid: x` (la ligne suivante DOIT être signalée) et `# ok: x` (elle NE DOIT PAS
  l'être). `semgrep --test rules/` compare. Une règle sans test, c'est comme du code sans test.

### Bandit (SAST spécialisé Python)
- Il parcourt l'AST Python avec des **plugins** (B104 écoute sur 0.0.0.0, B201 Flask debug,
  B608 SQL construit en chaîne, B105 mot de passe en dur...).
- Chaque résultat a une **sévérité** et une **confiance**. Le seuil ici : sévérité HIGH avec
  confiance MEDIUM au moins.
- On ne le lance pas sur `tests/` : les `assert` donneraient des centaines de B101 sans intérêt.

### Gitleaks (secrets)
- Des **expressions régulières** pour des formats connus (clé AWS `AKIA...`, jeton GitHub
  `ghp_...`, clé privée PEM) + un calcul d'**entropie** (une chaîne très aléatoire est
  suspecte).
- `gitleaks git` lit **tout l'historique** : un secret supprimé dans le dernier commit est
  toujours dans l'historique. La seule vraie réponse est de **révoquer** le secret.
- Dans ce dépôt il n'y a **aucun** secret, même faux : les tests et le script de démo
  génèrent des mots de passe aléatoires à chaque exécution.

### pip-audit (SCA Python)
- Il lit `requirements.txt`, puis interroge la base d'avis de sécurité (PyPI / **OSV**) pour
  chaque paquet et version.
- **Vrai résultat de ce projet :** au premier lancement, il a signalé Werkzeug 3.1.8
  (CVE-2026-102598) : `safe_join` acceptait des noms de périphériques Windows comme `NUL:`.
  Le portail sert `/static` avec `send_from_directory` et tourne sur Windows en local, donc
  ça me concernait. Correction : passage en 3.1.9, tests toujours verts (commit séparé).
- Il échoue sur **n'importe quel** avis, pas seulement high/critical, car beaucoup d'avis
  PyPI n'ont pas de score CVSS.

### Trivy (SCA + misconfig + secrets, dépôt et image)
- Il fait l'**inventaire** des paquets (Debian dans l'image, Python dans `requirements.txt`),
  puis compare avec sa base de vulnérabilités.
- `--ignore-unfixed` : on ne bloque que si une **version corrigée existe**, sinon le build
  serait rouge pour des choses que personne ne peut corriger.
- **Histoire importante :** en mars 2026, la chaîne de publication de Trivy a été compromise
  (CVE-2026-33634) : binaires et images 0.69.4 malveillants, tags `trivy-action` détournés.
  Leçon : un outil de sécurité fait aussi partie de la **chaîne d'approvisionnement**. D'où
  ici : image officielle à une version postérieure, **épinglée par digest**, et pas d'action
  tierce.

### OWASP ZAP baseline (DAST passif)
- ZAP démarre, **explore** le site (spider) pendant environ une minute, puis applique des
  règles **passives** : il lit les réponses (en-têtes, cookies, formulaires) sans envoyer
  d'attaque. C'est pour ça qu'il est sans danger.
- `.zap/rules.tsv` : chaque règle peut être `IGNORE`, `INFO`, `WARN` ou `FAIL`. On passe en
  FAIL les règles qui correspondent à nos contrôles (CSP absente, cookie sans Secure,
  formulaire sans jeton anti-CSRF...). `-I` : les simples avertissements ne cassent pas le build.
- **Limite :** il ne se connecte pas, il ne voit donc que `/login`.

---

## 4. Faux positifs, faux négatifs et seuil de blocage

- **Faux positif (FP)** : l'outil signale un problème qui n'en est pas un. Exemple typique :
  Semgrep signale une f-string dans `execute()` alors qu'elle ne contient qu'une liste de
  colonnes constante. Coût : du temps perdu et, à force, des développeurs qui ignorent l'outil.
- **Faux négatif (FN)** : un vrai problème que l'outil ne voit pas. Exemple : un IDOR. Coût :
  une fausse confiance. **Les FN sont plus dangereux** parce qu'on ne les voit pas.
- Ce que j'ai fait contre les FP : écrire le code pour qu'il n'en provoque pas (SQL en
  chaînes littérales, donc **zéro** `# nosemgrep` et **zéro** `# nosec`) et limiter le blocage
  aux sévérités hautes.
- Ce que j'ai fait contre les FN : des tests écrits à la main pour la logique métier, des
  fixtures `ruleid` pour vérifier que mes règles détectent vraiment, et la **mutation** pour
  vérifier que mes tests détectent vraiment.
- **Seuil (quality gate)** : on bloque sur high/critical, on garde le reste comme rapport.
  Bloquer sur tout rend le pipeline rouge en permanence ; ne rien bloquer le rend décoratif.
- Si un FP arrive : on le **documente** (`# nosemgrep: id -- raison`), on ne désactive jamais
  la règle entière sans revue.

---

## 5. Les protections de l'application, expliquées

- **IDOR** (Insecure Direct Object Reference) : un client remplace `/orders/2` par
  `/orders/3`. Protection : la requête SQL contient `AND customer_id = ?`, donc la commande
  d'un autre client **n'existe pas** pour lui. Réponse 404 (et pas 403) pour ne pas révéler
  qu'elle existe.
- **CSRF** : un site piégé fait poster un formulaire par le navigateur de la victime, avec
  son cookie. Protection : un **jeton aléatoire** stocké dans la session et caché dans chaque
  formulaire ; le site piégé ne peut pas le lire. `SameSite=Lax` est une deuxième couche.
- **XSS** : du HTML/JS injecté dans une note. Protection : Jinja **échappe** `<` en `&lt;`, et
  la **CSP** interdit les scripts inline même si un échappement était oublié.
- **SQL injection** : les `?` envoient la valeur **séparément** du texte SQL ; la base ne
  peut pas la confondre avec du code.
- **Injection CSV** : une cellule qui commence par `=` est exécutée comme formule par Excel.
  Protection : on préfixe par `'`.
- **Cookies** : `Secure` (HTTPS seulement), `HttpOnly` (JavaScript ne peut pas le lire),
  `SameSite=Lax` (pas envoyé par les POST d'autres sites), préfixe `__Host-` (le navigateur
  exige Secure, Path=/ et pas de Domain).
- **Session Flask** : c'est un cookie **signé, pas chiffré**. On peut lire son contenu (le
  jeton CSRF), pas le modifier. Donc on n'y met jamais de secret. Limite : à la
  déconnexion, une **copie** volée du cookie reste valide jusqu'à expiration (30 min).
- **Mots de passe** : `scrypt` (lent et gourmand en mémoire, donc coûteux à casser), avec sel.
- **Throttling** : 5 échecs en 15 min par IP **et** par nom d'utilisateur → 429. Le compteur
  par nom bloque aussi l'attaque répartie sur plusieurs IP.
- **Énumération** : même message et même coût (hash factice) qu'un utilisateur existe ou non.

---

## 6. "Detection as code" et mutation testing

C'est la même idée que dans soc-detection-lab : **une règle de détection est du code, donc
elle se teste comme du code**.

- Les règles Semgrep ont des fixtures `ruleid` / `ok` : si je casse une règle, `semgrep --test`
  échoue en CI.
- Les tests de défense sont eux-mêmes testés par **mutation** : `scripts/mutation_check.py`
  copie le projet, enlève **une** protection (par exemple le filtre `customer_id`), lance
  pytest, et attend un échec. 16 protections, 16 mutants tués. Un mutant qui survit veut
  dire « cette protection n'a aucun test ».

---

## 7. Questions d'entretien (avec réponses modèles)

**Q1. Présente ton projet en une minute.**
J'ai construit un petit portail de commandes Flask pour une PME fictive, sécurisé dès la
conception, et un pipeline GitHub Actions qui lance SAST, scan de secrets, SCA, scan d'image
et DAST passif, avec un seuil bloquant sur high/critical. 78 tests prouvent les contrôles,
vérifiés par mutation, et j'ai écrit 7 règles Semgrep testées. C'est un lab, jamais déployé.

**Q2. Différence entre SAST, DAST et SCA ?**
SAST lit le code sans l'exécuter ; DAST attaque (ou observe) l'application qui tourne ; SCA
vérifie les dépendances contre les CVE connues. Ils sont complémentaires.

**Q3. Pourquoi des tests à la main si tu as six outils ?**
Parce qu'aucun outil ne sait que la commande 3 appartient à un autre client. L'IDOR est de la
logique métier. Les outils trouvent des motifs, les tests prouvent des règles métier.

**Q4. Qu'est-ce qu'un faux négatif, et pourquoi c'est pire qu'un faux positif ?**
Un vrai problème non signalé. Un FP coûte du temps ; un FN donne une fausse confiance.

**Q5. Comment tu évites que le pipeline soit toujours rouge ?**
Seuil sur high/critical, `--ignore-unfixed` pour Trivy, règles ZAP choisies en FAIL, et du
code écrit pour ne pas déclencher de FP. Le reste part en rapport (SARIF, artefacts).

**Q6. Comment marche une règle Semgrep ?**
Un motif qui ressemble à du code, avec des métavariables, appliqué sur l'arbre syntaxique.
On peut exclure des cas (`pattern-not`) ou suivre une donnée de la source au puits (mode taint).

**Q7. Comment tu sais que tes règles marchent ?**
Chaque règle a un fichier de test avec des lignes `ruleid` (doit matcher) et `ok` (ne doit
pas). `semgrep --test` tourne en CI : 7/7.

**Q8. Qu'est-ce que le mutation testing ?**
On casse volontairement le code (ici, on enlève une protection) et on vérifie qu'un test
échoue. Si aucun test n'échoue, le test ne protégeait rien.

**Q9. Comment tu protèges contre le CSRF ?**
Jeton aléatoire dans la session, vérifié en temps constant sur chaque POST, plus SameSite=Lax.

**Q10. 403 ou 404 quand un client demande la commande d'un autre ?**
404 : même réponse qu'une commande inexistante, donc on ne peut pas deviner quels numéros existent.

**Q11. Pourquoi une CSP sans `unsafe-inline` ?**
Si un échappement est oublié, le script injecté inline ne s'exécute quand même pas.

**Q12. pip-audit a-t-il trouvé quelque chose ?**
Oui, une vraie CVE dans Werkzeug 3.1.8 sur `safe_join` sous Windows. Le portail sert des
fichiers statiques et tourne sur Windows en local, donc j'ai mis à jour en 3.1.9 et relancé
les tests. C'est dans un commit séparé.

**Q13. Pourquoi épingler les actions par SHA et pas par tag ?**
Un tag peut être déplacé par quelqu'un qui contrôle le dépôt, c'est ce qui est arrivé à
`trivy-action` en mars 2026. Un SHA de commit ne peut pas changer.

**Q14. Pourquoi Dependabot avec un délai de 7 jours ?**
Pour ne pas installer une version publiée il y a une heure, qui pourrait être malveillante.
C'est d'ailleurs le registre Semgrep qui me l'a signalé.

**Q15. Que fait ZAP baseline exactement, et ses limites ?**
Il explore le site et lit les réponses sans attaquer. Limite : non authentifié, il ne voit que
la page de connexion. Étape suivante : un contexte authentifié.

**Q16. Un développeur commit une clé AWS puis la supprime. Que faire ?**
La révoquer immédiatement : elle reste dans l'historique git. Gitleaks scanne tout
l'historique pour cette raison. Réécrire l'historique ne suffit pas, des clones existent.

**Q17. Comment stockes-tu les mots de passe ?**
scrypt via Werkzeug, salé, 12 à 128 caractères. Jamais en clair, jamais dans les logs.

**Q18. Ton limiteur de tentatives tient-il en production ?**
Non : il est en mémoire et par processus. Avec plusieurs workers il faudrait Redis ou le
reverse proxy. Je l'écris dans les limites.

**Q19. Pourquoi l'application n'écoute que sur 127.0.0.1 ?**
Pour qu'elle ne soit jamais exposée sur le réseau. L'exposition, c'est le rôle d'un reverse
proxy durci avec TLS. Une règle Semgrep maison et Bandit B104 le surveillent.

**Q20. Qu'est-ce que tu ferais ensuite ?**
DAST authentifié, sessions côté serveur révocables, MFA, SBOM publié en CI, et une règle de
revue : chaque nouvelle route arrive avec son test d'autorisation.

**Q21. Qu'est-ce que l'OWASP ASVS par rapport au Top 10 ?**
Le Top 10 est une liste de sensibilisation des risques les plus fréquents ; l'ASVS est un
référentiel d'exigences vérifiables (par exemple V4.2.1 pour l'IDOR). Mon fichier
`docs/CONTROLS.md` relie chaque contrôle aux deux et au CWE.

---

## 8. Ligne de CV (honnête, format §7)

**Tant que le pipeline n'a pas tourné en vert sur GitHub :**

- **FR** — **AppSec DevSecOps Pipeline** (Python/Flask, Semgrep, Bandit, Trivy, ZAP) : portail
  web de lab sécurisé dès la conception (IDOR, CSRF, CSP, cookies, SQL paramétré), 78 tests de
  défense vérifiés par mutation (16/16) ; 7 règles Semgrep maison testées ; pipeline GitHub
  Actions écrit (SAST, secrets, SCA, image, DAST passif, seuil high/critical). Jamais déployé.
- **EN** — **AppSec DevSecOps Pipeline** (Python/Flask, Semgrep, Bandit, Trivy, ZAP): secure-by-
  design lab web portal (IDOR, CSRF, CSP, cookie flags, parameterized SQL), 78 defense tests
  checked by mutation (16/16); 7 custom Semgrep rules with tests; GitHub Actions pipeline
  written (SAST, secrets, SCA, image, passive DAST, high/critical gate). Never deployed.

**Quand le workflow `security` est vert sur GitHub** (et seulement à ce moment-là), remplacer
« pipeline GitHub Actions écrit » par « pipeline GitHub Actions qui bloque le build sur
high/critical » / "GitHub Actions pipeline that fails the build on high/critical findings".

**À ne jamais dire :**
- « déployé en production », « utilisé par AgriSouss », « application d'un client » ;
- « 0 vulnérabilité », « application inviolable », « 100 % sécurisée » ;
- « 0 faux positif » (les outils n'ont rien signalé sur ce petit code, ça ne prouve pas
  l'absence de faux positifs ni de failles) ;
- « pentest réalisé » : ZAP baseline est un scan passif, pas un test d'intrusion ;
- « couvre tout l'OWASP ASVS » : seulement les exigences listées dans CONTROLS.md, certaines
  partiellement.
