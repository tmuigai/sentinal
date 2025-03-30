
from app import app, socketio
from routes import *  # Import all routes 

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
