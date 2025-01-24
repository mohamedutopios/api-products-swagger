# Utiliser une image Node.js officielle
FROM node:16

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers de l'application
COPY package*.json ./
COPY . .

# Installer les dépendances
RUN npm install

# Exposer le port 3000
EXPOSE 3000

# Commande pour démarrer l'application
CMD ["node", "api-user.js"]
