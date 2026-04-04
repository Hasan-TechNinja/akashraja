# DogBuddy Backend

DogBuddy is a real-time social gaming platform designed to connect users through interactive memory matching challenges and proximity-based buddy discovery. This repository contains the robust Django-based backend that powers the mobile application, featuring live gameplay, secure social networking, and a tiered subscription model.

## 🚀 Key Features

### 🎮 Real-time Memory Match Gaming
- **Live Challenges**: Send and receive game challenges to/from friends or nearby users.
- **WebSocket Integration**: Powered by Django Channels and Redis for instantaneous game state synchronization.
- **Dynamic Board Generation**: Memory boards are generated dynamically based on selected categories and difficulty levels.
- **State Management**: High-performance game state tracking using Redis to ensure zero-latency tile flips and scoring.

### 📍 Social & Proximity Discovery
- **Proximity Radar**: Discover nearby users in real-time, categorized by their current activity and buddy status.
- **Friendship System**: Comprehensive friend management including requests, approvals, and "Last Played" history.
- **Real-time Chat**: Integrated messaging system for buddies to communicate and coordinate playdates.

### 👤 User Profiles & Personalization
- **Multimedia Albums**: Users can maintain personal albums with images and associated audio files.
- **Customizable Profiles**: Detailed user profiles with unique Player IDs, custom avatars, and online status tracking.
- **Device Synchronization**: Seamlessly track and update device IDs for push notifications.

### 💳 Monetization & Subscriptions
- **Tiered Plans**: Support for Free, Monthly, and Yearly subscription models.
- **Stripe Integration**: Fully integrated with Stripe for secure payment processing and automated subscription management via webhooks.
- **Feature Gating**: Tier-based access to premium features of the platform.

### 🛡️ Security & Authentication
- **JWT Authentication**: Secure API access using SimpleJWT with token rotation and blacklisting.
- **Verification Flows**: Email verification for new registrations and secure password reset mechanisms.
- **Social Login Support**: Foundation for integrating external social authentication providers.

---

## 🛠️ Tech Stack

- **Core Framework**: [Django 4.2+](https://www.djangoproject.com/)
- **API Engine**: [Django REST Framework](https://www.django-rest-framework.org/)
- **Real-time Communication**: [Django Channels](https://channels.readthedocs.io/), Daphne, Socket.IO
- **Primary Database**: [PostgreSQL](https://www.postgresql.org/)
- **State Store & Message Broker**: [Redis](https://redis.io/)
- **Payment Processing**: [Stripe](https://stripe.com/)
- **Static Assets**: [WhiteNoise](https://whitenoise.readthedocs.io/)
- **Configuration**: [Python-Decouple](https://pypi.org/project/python-decouple/)

---

## ⚙️ Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Hasan-TechNinja/akashraja.git
cd akashraja
```

### 2. Set Up Virtual Environment
```bash
python -m venv env
source env/bin/activate  # On Windows use `env\Scripts\activate`
pip install -r requirements.txt
```

### 3. Environment Configuration
Create a `.env` file in the root directory and populate it with your credentials (refer to `.env.example`):
```ini
SECRET_KEY=your_secret_key
DEBUG=True
DB_NAME=akashraja
DB_USER=your_db_user
DB_PASS=your_db_password
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
STRIPE_SECRET_KEY=sk_test_...
```

### 4. Database Migrations
```bash
python manage.py migrate
```

### 5. Start Redis
Ensure you have a Redis server running locally or via Docker:
```bash
docker run -p 6379:6379 -d redis
```

### 6. Run the Application
For regular development:
```bash
python manage.py runserver
```
For WebSocket support (ASGI):
```bash
daphne -p 8000 akashraja.asgi:application
```

---

## 📂 Project Structure

- `akashraja/`: Core settings and routing.
- `authentication/`: User registration, JWT management, and verification logic.
- `social/`: Friendship graphs, profiles, and buddy discovery systems.
- `game/`: Memory match logic, Redis-backed sessions, and real-time event handling.
- `payment/`: Stripe integration, subscription plans, and webhook handlers.
- `home/`: Shared models for categories, options, and user albums.

---

## 📜 License
This project is licensed under the MIT License.
