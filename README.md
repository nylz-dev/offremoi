# 🎁 OffreMoi

**Wishlist anonyme pour créateurs FR** — Clone de [Throne.com](https://throne.com) fait pour les créateurs français.

## Concept

Les fans peuvent envoyer des cadeaux depuis la wishlist d'un créateur **sans jamais voir son adresse**.  
Le créateur gagne des commissions Amazon sur chaque achat.

## Lancer en local

```bash
npm install
npm start
# Accessible sur http://localhost:3457
```

## Routes

| Méthode | Route | Description |
|---------|-------|-------------|
| GET | `/` | Page d'accueil |
| GET | `/:username` | Profil du créateur |
| GET | `/api/wishlists/:username` | Données JSON de la wishlist |
| POST | `/api/wishlists` | Créer une wishlist |
| POST | `/api/wishlists/:username/items` | Ajouter un item |

## Demo

Visitez `/nylz` pour voir un exemple de profil créateur.

## Stack

- **Backend:** Node.js + Express
- **Frontend:** HTML/CSS/JS vanilla (SPA)
- **DB:** JSON file (`data/wishlists.json`)

## TODO

- [ ] Authentification créateur
- [ ] Affiliation Amazon (`?tag=offremoi-21`)
- [ ] Images produits automatiques (API Amazon)
- [ ] Dashboard créateur (stats, commandes reçues)
- [ ] Notifications email/Discord quand un fan offre un cadeau
