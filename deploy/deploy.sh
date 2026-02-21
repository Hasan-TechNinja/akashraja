#!/bin/bash

# Configuration
PROJECT_DIR="/home/hasan/akashraja"
VENV_DIR="$PROJECT_DIR/env"

echo "🚀 Starting deployment..."

cd $PROJECT_DIR

# Pull latest code (optional, if using git)
# git pull origin main

# Activate virtual environment
source $VENV_DIR/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Run migrations
echo "🗄️ Running migrations..."
python manage.py migrate

# Collect static files
echo "📑 Collecting static files..."
python manage.py collectstatic --no-input

# Restart services
echo "♻️ Restarting services..."
sudo systemctl restart gunicorn
sudo systemctl restart daphne
sudo systemctl restart nginx

echo "✅ Deployment complete!"
