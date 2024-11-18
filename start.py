import json
from flask import Flask, render_template, jsonify, url_for
from threading import Thread
import webbrowser
from pOSf import PassiveOSFingerprinter

app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/results')
def results():
    return jsonify(fingerprinter.get_results())

def start_flask():
    app.run(host='127.0.0.1', port=5000)

if __name__ == "__main__":
    fingerprinter = PassiveOSFingerprinter()
    
    # Start Flask server in a separate thread
    flask_thread = Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # Open web browser
    webbrowser.open('http://127.0.0.1:5000')

    try:
        # Start packet capture in main thread
        fingerprinter.start_sniffing()
    except KeyboardInterrupt:
        print("\nStopping packet capture...")
        fingerprinter.is_running = False