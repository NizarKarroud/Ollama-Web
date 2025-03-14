from flask import Flask, request, Response , jsonify
import requests
import json , os  
import uuid
from datetime import datetime , timezone , timedelta

from flask_cors import CORS  
from flask_jwt_extended import create_access_token , JWTManager ,jwt_required , get_jwt_identity  , decode_token
from werkzeug.security import generate_password_hash , check_password_hash
from dotenv import load_dotenv

from cassandra.cluster import Cluster
from cassandra.cluster import NoHostAvailable


load_dotenv()

app = Flask(__name__)
CORS(app, expose_headers=["Authorization" , 'Chat-ID'])

app.config["JWT_SECRET_KEY"] = os.getenv("SECRET_KEY")  

OLLAMA_URL = "http://192.168.1.10:11434/api/generate"
MODEL_NAME = "llama3:8b"

jwt = JWTManager(app)
cluster = Cluster(["192.168.1.10 ", "192.168.1.11" , "192.168.1.12"])

session = cluster.connect()
session.set_keyspace("user_data")

@app.route('/ask', methods=['POST'])
@jwt_required()
def ask_ollama():
    user_input = request.json.get("user_input", "")
    chat_id = request.json.get("chat_id") 

    if not user_input:
        return jsonify({"msg": "No input provided"}), 400

    user_id = get_jwt_identity()  

    if not chat_id:
        chat_id = uuid.uuid4()
        created_at = datetime.now(timezone.utc)

        title_response = requests.post(
            OLLAMA_URL,
            json={"model": MODEL_NAME, "prompt": f"Generate a very short and concise title for this conversation:\n{user_input}"}
        )
        title = ""
        for line in title_response.text.split("\n"):  
            if line.strip():  
                try:
                    data = json.loads(line)  
                    title += data.get("response", "") 
                except json.JSONDecodeError:
                    print("Skipping invalid JSON:", line)

        title = title.strip('"')


        session.execute("""
            INSERT INTO chats (chat_id, user_id, created_at, title)
            VALUES (%s, %s, %s, %s)
        """, [chat_id, user_id, created_at, title])
    else:
        chat_id = uuid.UUID(chat_id) 
    message_id = uuid.uuid4()
    timestamp = datetime.now(timezone.utc)
    session.execute("""
        INSERT INTO messages (chat_id, message_id, text, timestamp)
        VALUES (%s, %s, %s, %s)
    """, [chat_id, message_id, user_input, timestamp])

    def stream_response():
        response = requests.post(
            OLLAMA_URL,
            json={"model": MODEL_NAME, "prompt": user_input},
            stream=True
        )

        bot_message = ""
        for line in response.iter_lines():
            if line:
                chunk = json.loads(line.decode("utf-8"))
                bot_message += chunk.get("response", "").strip("")
                yield chunk.get("response", "")
                if chunk.get("done", False):
                    break

        bot_message_id = uuid.uuid4()
        session.execute("""
            INSERT INTO messages (chat_id, message_id, text, timestamp)
            VALUES (%s, %s, %s, %s)
        """, [chat_id, bot_message_id, bot_message, datetime.now(timezone.utc)])

    return Response(stream_response(), content_type='text/plain', headers={"Chat-ID": str(chat_id)})


@app.route('/title', methods=['POST'])
@jwt_required()
def get_chat_title():
    
    data = request.get_json()
    chat_id = data.get('chat_id')

    if not chat_id:
        return jsonify({"error": "Missing chat_id"}), 400

    try:
        query = "SELECT title FROM chats WHERE chat_id = %s"
        result = session.execute(query, (uuid.UUID(chat_id),))
        
        chat_title = result.one()
        if chat_title:
            return chat_title.title, 200  
        else:
            return "New Chat", 200  

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get("username", "")
    password = request.json.get("password", "")
    
    # Ensure username and password are provided
    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    # Check if the user exists
    user_check = session.execute("SELECT username, password_hash FROM users WHERE username = %s", [username])

    user = user_check.one()
    print(user)
    if not user:
        return jsonify({"msg": "Invalid username or password"}), 401

    # Check if the password is correct
    if not check_password_hash(user.password_hash, password):
        return jsonify({"msg": "Invalid username or password"}), 40

    access_token = create_access_token(identity=username , expires_delta=timedelta(hours=24))

    response = jsonify({
        "status": "correct credentials"
    })

    response.headers['Authorization'] = f'Bearer {access_token}'
    return response, 200


@app.route('/chats', methods=['GET'])
@jwt_required()
def get_chats():
    user_id = get_jwt_identity() 
    try:
        query = "SELECT chat_id, title, created_at FROM chats WHERE user_id = %s ALLOW FILTERING"
        result = session.execute(query, [user_id])
        print(result)
        chats = []
        for row in result:
            chats.append({
                "chat_id": str(row.chat_id),
                "title": row.title,
                "created_at": row.created_at.isoformat()  
            })

        return jsonify({"chats": chats}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/chat/<chat_id>', methods=['GET'])
@jwt_required()
def get_chat_messages(chat_id):
    try:
        query = "SELECT message_id, text, timestamp FROM messages WHERE chat_id = %s ALLOW FILTERING"
        result = session.execute(query, [uuid.UUID(chat_id)])

        messages = []
        for row in result:
            messages.append({
                "message_id": str(row.message_id),
                "text": row.text,
                "timestamp": row.timestamp.isoformat()
            })

        messages.sort(key=lambda msg: msg['timestamp'])
        return jsonify({"messages": messages}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get("username", "")
    password = request.json.get("password", "")

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    # Hash the password
    password_hash = generate_password_hash(password)

    # Check if user already exists
    user_check = session.execute("SELECT username FROM users WHERE username = %s", [username])
    if user_check.one():
        return jsonify({"msg": "User already exists"}), 409

    # Insert user into database
    session.execute("""
        INSERT INTO users (username, password_hash, created_at)
        VALUES (%s, %s, toTimestamp(now()))
    """, [username, password_hash])

    return jsonify({"msg": "User registered successfully"}), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

# curl -X POST http://localhost:5000/ask -H "Content-Type: application/json" -d "{\"user_input\": \"Why is the sky blue?\"}"


