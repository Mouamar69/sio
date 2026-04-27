# Forum Insecure — Projet SIO

Application web de forum intentionnellement vulnérable, réalisée à des fins pédagogiques dans le cadre du BTS SIO. Elle illustre des failles de sécurité classiques ainsi que leurs corrections.

---

## Architecture

```
sio/
├── docker-compose.yml
├── frontend_sio/          # Interface web (HTML/CSS/JS — Nginx)
│   ├── login.html
│   ├── register.html
│   ├── index.html
│   └── style.css
└── sio_backend/           # API REST (PHP — Apache)
    ├── api/
    │   ├── login.php
    │   ├── register.php
    │   ├── posts.php
    │   └── users.php
    ├── dotenv.php
    ├── init_db.php
    └── .env
```

| Service  | Technologie       | Port |
|----------|-------------------|------|
| Frontend | Nginx + HTML/JS   | 3000 |
| Backend  | Apache + PHP      | 8081 |
| Base de données | MySQL 8.0  | 3306 |

---

## Lancer le projet (Docker)

```bash
git clone <url-du-repo>
cd sio
docker compose up --build
```

- Frontend : [http://localhost:3000](http://localhost:3000)
- API backend : [http://localhost:8081](http://localhost:8081)

### Initialiser la base de données

```bash
docker compose exec backend php /var/www/html/init_db.php
```

### Comptes par défaut

| Utilisateur | Mot de passe  | Rôle  |
|-------------|---------------|-------|
| `admin`     | `password123` | admin |
| `guest`     | `guest123`    | user  |

---

## Déploiement manuel (sans Docker)

### Prérequis

- Apache avec PHP (`mysqli`, `pdo_mysql`)
- MySQL ou MariaDB

```bash
apt install php php-mysqli php-pdo-mysql
systemctl restart apache2
apt install mariadb-server
sudo mariadb
ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY 'root';
FLUSH PRIVILEGES;
```

### Configuration

1. Renseigner le fichier `.env` dans `sio_backend/` :
   ```ini
   DB_HOST=localhost
   DB_USER=your_db_user
   DB_PASS=your_db_password
   DB_NAME=backend
   ```

2. Initialiser la base :
   ```bash
   php sio_backend/init_db.php
   ```

---

## Documentation des failles de sécurité

Les vulnérabilités ci-dessous ont été introduites intentionnellement. Chaque section indique l'état initial (code vulnérable), la technique d'attaque, et la correction appliquée.

---

### Faille 1 — Injection SQL

**Fichiers concernés :** `api/login.php`, `api/register.php`  
**Catégorie OWASP :** A03:2021 – Injection

**Description**  
Les entrées utilisateur étaient interpolées directement dans les requêtes SQL. Un attaquant pouvait manipuler la logique de la requête pour contourner l'authentification ou exfiltrer des données.

**Exemple d'attaque**  
Saisir comme nom d'utilisateur :
```
' OR '1'='1
```
La requête devenait :
```sql
SELECT * FROM users WHERE username = '' OR '1'='1' AND password = ''
```
Résultat : retourne tous les utilisateurs → connexion sans credentials valides.

**Code vulnérable**
```php
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = $conn->query($query);
```

**Correction appliquée** — Requêtes préparées (`prepare` + `bind_param`)
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
```

---

### Faille 2 — Stockage des mots de passe en clair

**Fichiers concernés :** `api/register.php`, `api/login.php`  
**Catégorie OWASP :** A02:2021 – Cryptographic Failures

**Description**  
Les mots de passe étaient stockés et comparés en texte clair dans la base de données. En cas de fuite SQL ou d'accès non autorisé à la base, tous les mots de passe seraient immédiatement lisibles.

**Code vulnérable**
```php
// Inscription — stockage en clair
$query = "INSERT INTO users (username, email, password) VALUES ('$username', '$email', '$password')";

// Connexion — comparaison en clair via SQL
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

**Correction appliquée** — Hachage bcrypt + `password_verify()`
```php
// Inscription
$hashedPassword = password_hash($password, PASSWORD_BCRYPT);

// Connexion
if (!password_verify($password, $row['password'])) {
    // mot de passe incorrect
}
```

---

### Faille 3 — Contrôle d'accès manquant (IDOR)

**Fichier concerné :** `api/posts.php`  
**Catégorie OWASP :** A01:2021 – Broken Access Control

**Description**  
N'importe quel utilisateur connecté pouvait supprimer le message d'un autre utilisateur en envoyant une requête DELETE avec l'ID du post ciblé. Aucune vérification de propriété n'était effectuée.

**Exemple d'attaque**
```http
DELETE http://localhost:8081/api/posts.php?id=5
```
Supprime le message n°5, même s'il appartient à un autre utilisateur.

**Code vulnérable**
```php
// Suppression sans vérification du propriétaire
$stmt = $conn->prepare("DELETE FROM posts WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
```

**Correction appliquée** — Vérification du propriétaire ou du rôle admin
```php
$check = $conn->prepare("SELECT user_id FROM posts WHERE id = ?");
$check->bind_param("i", $id);
$check->execute();
$post = $check->get_result()->fetch_assoc();

if ($post['user_id'] !== $_SESSION['user_id'] && $_SESSION['role'] !== 'admin') {
    http_response_code(403);
    echo json_encode(['error' => 'Forbidden: you can only delete your own posts']);
    exit();
}
```

---

### Faille 4 — Usurpation d'identité à la publication (user_id côté client)

**Fichier concerné :** `api/posts.php` (méthode POST)  
**Catégorie OWASP :** A01:2021 – Broken Access Control

**Description**  
Lors de la création d'un message, le `user_id` est envoyé par le client dans le corps de la requête JSON. Un attaquant peut falsifier cette valeur pour publier un message sous l'identité d'un autre utilisateur.

**Exemple d'attaque**
```http
POST http://localhost:8081/api/posts.php
Content-Type: application/json

{"user_id": 1, "content": "Message publié sous l'identité de l'admin"}
```

**Code vulnérable**
```php
$user_id = isset($input['user_id']) ? intval($input['user_id']) : 0;
// user_id vient du client — non vérifié
$stmt = $conn->prepare("INSERT INTO posts (user_id, content) VALUES (?, ?)");
$stmt->bind_param("is", $user_id, $content);
```

**Correction** — Toujours récupérer l'identité depuis la session serveur
```php
$user_id = $_SESSION['user_id']; // source de confiance : serveur
```

---

### Faille 5 — Champ mot de passe visible (`type="text"`)

**Fichiers concernés :** `login.html`, `register.html`  
**Catégorie OWASP :** A02:2021 – Cryptographic Failures (exposition visuelle)

**Description**  
Les champs mot de passe sont déclarés avec `type="text"` au lieu de `type="password"`. Le mot de passe saisi est donc affiché en clair à l'écran, visible par toute personne regardant l'écran (shoulder surfing) et non masqué dans l'historique du navigateur.

**Code vulnérable**
```html
<input type="text" id="password" placeholder="Entrez votre mot de passe">
```

**Correction**
```html
<input type="password" id="password" placeholder="Entrez votre mot de passe">
```

---

### Faille 6 — XSS (Cross-Site Scripting) via messages d'erreur

**Fichiers concernés :** `login.html`, `register.html`, `index.html`  
**Catégorie OWASP :** A03:2021 – Injection (XSS)

**Description**  
Les messages d'erreur ou de succès retournés par l'API sont injectés directement dans le DOM via `innerHTML` sans échappement. Si le serveur réfléchit une valeur saisie par l'utilisateur (ex. une adresse email invalide), un attaquant peut y injecter du code HTML/JavaScript.

**Exemple d'attaque**  
Saisir comme email :
```
<img src=x onerror="alert('XSS')">
```
Si le backend renvoie cette valeur dans le champ `error`, elle est exécutée par le navigateur.

**Code vulnérable**
```js
msg.innerHTML = `<p style="color: red;">${result.error}</p>`;
```

**Correction** — Utiliser `textContent` ou échapper le HTML
```js
const p = document.createElement('p');
p.style.color = 'red';
p.textContent = result.error; // jamais innerHTML avec une valeur externe
msg.appendChild(p);
```

---

### Faille 7 — Credentials par défaut faibles

**Fichier concerné :** `init_db.php`  
**Catégorie OWASP :** A07:2021 – Identification and Authentication Failures

**Description**  
La base de données est initialisée avec des comptes prédictibles. En environnement de production, ces comptes constituent une porte d'entrée immédiate pour un attaquant.

| Compte | Mot de passe  | Risque |
|--------|---------------|--------|
| admin  | `password123` | Accès admin complet |
| guest  | `guest123`    | Accès utilisateur |

**Correction** — Forcer le changement de mot de passe au premier lancement, ou générer un mot de passe aléatoire à l'initialisation.

---

## Résumé des failles

| # | Faille | Fichier(s) | OWASP | Statut |
|---|--------|------------|-------|--------|
| 1 | Injection SQL | `api/login.php`, `api/register.php` | A03 | Corrigé |
| 2 | Mots de passe en clair | `api/register.php`, `api/login.php` | A02 | Corrigé |
| 3 | IDOR — suppression de post | `api/posts.php` | A01 | Corrigé |
| 4 | user_id fourni par le client | `api/posts.php` | A01 | Vulnérable |
| 5 | Champ password en `type="text"` | `login.html`, `register.html` | A02 | Vulnérable |
| 6 | XSS via innerHTML | `login.html`, `register.html`, `index.html` | A03 | Vulnérable |
| 7 | Credentials par défaut faibles | `init_db.php` | A07 | Vulnérable |
