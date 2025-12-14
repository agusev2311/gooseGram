import flask
from flask_sqlalchemy import SQLAlchemy
import telebot
import super_secret_config
import threading
from datetime import datetime, timezone
import secrets
import os


db = SQLAlchemy()

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.BigInteger, primary_key=True)

    public_key = db.Column(db.String(512), unique=True)

    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    verify_secret = db.Column(db.String(128), default=lambda: secrets.token_hex(64))
    is_active = db.Column(db.Boolean, default=False, nullable=False)

    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self):
        return f"<User id={self.id} verified={self.is_verified}>"

def create_user(tg_id: int):
    user = User(
        id=tg_id,

    )
    db.session.add(user)
    db.session.commit()

def verify_user(tg_id: int, public_key: str):
    user = User.query.filter_by(id=tg_id).first()
    if user:
        user.is_verified = True
        user.is_active = True
        user.public_key = public_key
        user.updated_at = datetime.now(timezone.utc)
        db.session.commit()
        return True
    return False

bot = telebot.TeleBot(super_secret_config.TELEBOT_TOKEN)

@bot.message_handler(commands=['start'])
def send_welcome(message):
    with app.app_context():
        if User.query.filter_by(id=message.from_user.id).first() is None:
            bot.reply_to(message, "You are not registered. Please register via the web interface first.")
            return
        user = User.query.filter_by(id=message.from_user.id).first()
        if not user.is_verified:
            bot.send_message(message.from_user.id, user.verify_secret)
        else:
            bot.send_message(message.from_user.id, "You are already verified!")

def run_bot():
    bot.infinity_polling()

app = flask.Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return "https://github.com/agusev2311/gooseGram"

@app.route("/api/v1/register", methods=["POST"])
def register_user():
    data = flask.request.json
    userid = data.get("userid")
    if userid is None:
        return flask.jsonify({"error": "userid is required"}), 400
    if userid <= 0:
        return flask.jsonify({"error": "invalid userid"}), 400
    if not str(userid).isdigit():
        return flask.jsonify({"error": "invalid userid"}), 400
    existing_user = User.query.filter_by(id=userid).first()
    if existing_user:
        return flask.jsonify({"error": "user already registered"}), 400
    create_user(userid)
    return flask.jsonify({"status": "user registered successfully. Now send /start to our bot. ID: 7169656470"}), 200

@app.route("/api/v1/verify", methods=["POST"])
def verify():
    data = flask.request.json
    userid = data.get("userid")
    public_key = data.get("public_key")
    verify_secret = data.get("verify_secret")
    if userid is None or public_key is None or verify_secret is None:
        return flask.jsonify({"error": "userid, public_key and verify_secret are required"}), 400
    user = User.query.filter_by(id=userid).first()
    if user is None:
        return flask.jsonify({"error": "user not found"}), 404
    if user.is_verified:
        return flask.jsonify({"error": "user already verified"}), 400
    if user.verify_secret != verify_secret:
        return flask.jsonify({"error": "invalid verify_secret"}), 400
    if verify_user(userid, public_key):
        return flask.jsonify({"status": "user verified successfully"}), 200
    else:
        return flask.jsonify({"error": "user not found"}), 404

@app.route("/api/v1/get_public_key/<int:userid>", methods=["GET"])
def get_public_key(userid):
    user = User.query.filter_by(id=userid).first()
    if user is None:
        return flask.jsonify({"error": "user not found"}), 404
    if not user.is_verified:
        return flask.jsonify({"error": "user not verified"}), 400
    return flask.jsonify({"public_key": user.public_key}), 200

if __name__ == '__main__':
    # Only start bot in the main process, not in Flask's reloader
    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
        threading.Thread(target=run_bot, daemon=True).start()

    app.run(host="0.0.0.0", debug=True, port=8080, use_reloader=True)