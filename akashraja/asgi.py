import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'akashraja.settings')
django_asgi_app = get_asgi_application()

# --- Socket.IO setup ---
import socketio
from game.sockets import sio  # <-- we’ll create this next

# Mount Socket.IO at /ws/socket.io/
application = socketio.ASGIApp(sio, django_asgi_app, socketio_path="ws/socket.io")
