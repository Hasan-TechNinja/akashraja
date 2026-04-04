# DogBuddy Technical Documentation

This document provides a detailed overview of the DogBuddy backend architecture, API design, and core systems.

## 🏘️ Architecture Overview

The DogBuddy backend is built on a modern, asynchronous Python stack:
- **Django**: Primary web framework for REST APIs and management.
- **Django Channels (ASGI)**: Handles WebSocket connections for real-time gaming.
- **Redis**: Used as the Channel Layer for message passing and as a fast in-memory store for active game states.
- **PostgreSQL**: Reliable persistent storage for user data, social graphs, and transaction history.
- **Stripe**: External payment gateway integration.

---

## 🔑 Authentication System

The system uses JWT (JSON Web Token) for stateless authentication.

### Flow:
1. **Registration**: `/auth/register/` (collects email, username, password).
2. **Email Verification**: Sends a code to the user's email. Verify via `/auth/verify-email/`.
3. **Login**: `/auth/login/` returns a Bearer token.
4. **Token Refresh**: Use `/api/token/refresh/` for seamless sessions.
5. **Security**: Supports password reset and account deletion.

---

## 🎯 Game Engine (Memory Match)

The game engine is designed for low-latency, real-time peer-to-peer play.

### State Management:
- **Database**: Stores `GameChallenge` and `GameSession` metadata (ended games, final scores).
- **Redis**: Stores active game data, including:
    - **Board**: The shuffled list of images for the match.
    - **Revealed**: A set of indices already matched.
    - **Turn**: The user ID of the current player.
    - **Scores**: Real-time counters for matched pairs.

### WebSocket Events:
Clients connect to `ws/game/<session_id>/` or `ws/game/`.
- **`flip`**: Flip two tiles. If they match, scores increment and tiles stay revealed.
- **`game_state`**: Broadcasted whenever the board changes.
- **`game_end`**: Triggered when all tiles are matched; results are persisted to the DB.

---

## 👥 Social Infrastructure

### Friendship Model:
- **Symmetric Relationships**: Friendships are stored in the `Friendship` model.
- **Friend Requests**: `/social/friends/add/` allows adding users by their unique `player_id`.
- **Proximity Discovery**: (Planned/In Development) Uses geolocation data to suggest nearby buddies.

### User Multimedia:
- **Albums**: Users can create albums (`/home/albums/`).
- **Media Content**: Each album can host multiple images and 1 associated audio clip.

---

## 💳 Payment & Subscriptions

Monetization is handled through tiered plans.

### Implementation:
- **Plans**: Defined in `SubscriptionPlan`. Types: `free`, `monthly`, `yearly`.
- **Stripe Integration**: 
    - Checkout sessions are created via backend services.
    - Webhook (`/pay/webhooks/stripe/`) listens for `subscription_updated` and `payment_succeeded` events to sync local state.
- **Grace Periods**: Managed via `current_period_end` timestamps from Stripe.

---

## 🚀 Deployment & DevOps

### Services:
- **Gunicorn**: Serves standard HTTP/REST requests.
- **Daphne**: Serves WebSocket/ASGI traffic.
- **Nginx**: Reverse proxy, SSL termination, and static/media file serving.
- **Redis**: Running as a background service for caching and channels.

### Relevant Config Files:
- `deploy/nginx.conf`: Nginx routing configuration.
- `deploy/gunicorn.service`: Systemd unit for Gunicorn.
- `deploy/daphne.service`: Systemd unit for Daphne.
- `deploy/deploy.sh`: Automated deployment script for pulling code, migrating, and restarting services.

---

## 🛠️ API Reference Summary

### Authentication (`/auth/`)
- `POST /register/`, `POST /login/`, `POST /logout/`
- `POST /verify-email/`, `POST /forgot-password/`
- `POST /social-login/`

### Social & Profile (`/social/`)
- `GET /me/`: Current user basic info.
- `GET /friends/`: List of confirmed friends.
- `POST /friends/add/`: Send request via `player_id`.
- `GET /last-played/`: Recent game partners.
- `PUT /profile/device-id/`: Update FCM/Device token.

### Game (`/game/`)
- `POST /challenges/`: Create a new game challenge.
- `GET /challenges/pending/`: List of active invitations.
- `GET /sessions/my/active/`: Resume unfinished game.
- `WS /ws/game/`: Real-time game socket.

### Payments (`/pay/`)
- `GET /subscription-plans/`: Available tiers.
- `POST /webhooks/stripe/`: Stripe server-to-server notifications.
