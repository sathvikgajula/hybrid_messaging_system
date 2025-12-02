# server.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import database

app = FastAPI()

class RegisterRequest(BaseModel):
    username: str
    public_keys: dict

class MessageRequest(BaseModel):
    sender: str
    recipient: str
    payload: dict  # Contains 'ciphertext', 'aes_key_enc', 'scheme', 'signature'

@app.get("/")
def home():
    return {"status": "running", "service": "Hybrid Messaging Relay"}

@app.post("/register")
def register(req: RegisterRequest):
    success = database.register_user_db(req.username, req.public_keys)
    if not success:
        raise HTTPException(status_code=400, detail="Username taken")
    return {"msg": "Registered successfully"}

@app.get("/keys/{username}")
def get_keys(username: str):
    keys = database.get_public_keys(username)
    if not keys:
        raise HTTPException(status_code=404, detail="User not found")
    return keys

@app.post("/send")
def send_message(req: MessageRequest):
    # Verify recipient exists first
    if not database.get_public_keys(req.recipient):
        raise HTTPException(status_code=404, detail="Recipient not found")
    
    database.store_message(req.sender, req.recipient, req.payload)
    return {"msg": "Message queued for delivery"}

@app.get("/inbox/{username}")
def get_inbox(username: str):
    msgs = database.fetch_messages(username)
    return {"messages": msgs}