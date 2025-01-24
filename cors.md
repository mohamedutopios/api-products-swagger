
### **1. Préparer l’instance EC2**
#### **Étape 1 : Lancer une instance EC2**
1. Connectez-vous à AWS Management Console.
2. Lancez une instance EC2 Ubuntu (par exemple, Ubuntu 20.04 LTS).
3. Configurez un groupe de sécurité pour ouvrir les ports nécessaires :
   - **Port 22** : Pour SSH.
   - **Port 3000** : Pour accéder à votre API.

#### **Étape 2 : Connectez-vous à l’instance EC2**
Depuis votre terminal local, utilisez SSH pour vous connecter :
```bash
ssh -i your-key.pem ubuntu@your-ec2-public-ip
```

---

### **2. Installer les dépendances sur l’instance**
#### **Étape 1 : Mettre à jour le système**
```bash
sudo apt update && sudo apt upgrade -y
```

#### **Étape 2 : Installer Node.js et npm**
1. Installez Node.js (par exemple, la version LTS) :
   ```bash
   curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
   sudo apt install -y nodejs
   ```
2. Vérifiez l'installation :
   ```bash
   node -v
   npm -v
   ```

#### **Étape 3 : Installer Git**
Installez Git pour cloner votre projet :
```bash
sudo apt install git -y
```

---

### **3. Télécharger et configurer le projet**
#### **Étape 1 : Cloner votre projet**
Cloner votre projet depuis un dépôt Git (par exemple, GitHub) :
```bash
git clone https://github.com/username/api-user.git
```

Accédez au répertoire cloné :
```bash
cd api-user
```

#### **Étape 2 : Installer les dépendances**
Installez les dépendances nécessaires avec npm :
```bash
npm install
```

#### **Étape 3 : Configurer votre projet**
Si votre projet utilise des variables d’environnement, créez un fichier `.env` :
```bash
nano .env
```

Ajoutez vos variables d'environnement :
```plaintext
PORT=3000
API_VERSION=/v2
```

---

### **4. Démarrer l’API**
#### **Étape 1 : Exécuter le projet**
Démarrez le serveur avec Node.js :
```bash
node app.js
```

#### **Étape 2 : Vérifier le fonctionnement**
1. Notez l'**IP publique** de votre instance EC2 (visible dans la console AWS).
2. Accédez à votre API depuis un navigateur ou avec `curl` :
   ```bash
   curl http://your-ec2-public-ip:3000/v2/users
   ```

---

### **5. Configurer un processus permanent**
Pour éviter que le projet ne s'arrête lorsque vous fermez votre session SSH, utilisez **PM2**.

#### **Étape 1 : Installer PM2**
Installez PM2 globalement :
```bash
sudo npm install -g pm2
```

#### **Étape 2 : Lancer le projet avec PM2**
Démarrez le projet avec PM2 :
```bash
pm2 start app.js --name api-user
```

#### **Étape 3 : Configurer PM2 pour redémarrer automatiquement**
Configurez PM2 pour qu'il redémarre automatiquement après un redémarrage de l'instance :
```bash
pm2 startup
pm2 save
```

---

### **6. Configurer un nom de domaine (facultatif)**
Si vous avez un nom de domaine, configurez-le pour pointer vers votre instance EC2 avec un enregistrement **A**.

---

### **7. Résolution des problèmes**
- **API inaccessible ?**
  - Vérifiez que le port 3000 est ouvert dans le groupe de sécurité.
  - Assurez-vous que l'API fonctionne avec :
    ```bash
    curl http://localhost:3000/v2/users
    ```
- **Problèmes de dépendances ?**
  - Réinstallez les modules :
    ```bash
    rm -rf node_modules package-lock.json
    npm install
    ```

---

### **Résumé des commandes**
```bash
# Mise à jour et installation
sudo apt update && sudo apt upgrade -y
sudo apt install -y nodejs git

# Cloner et configurer le projet
git clone https://github.com/username/api-user.git
cd api-user
npm install

# Démarrer le projet
node app.js

# Installer et configurer PM2
sudo npm install -g pm2
pm2 start app.js --name api-user
pm2 save
pm2 startup
```

