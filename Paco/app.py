from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
import time
import uuid
import os
import requests
import telebot
from telebot import types
from datetime import datetime
import random
from telegram_paco import TelegramPaco
from reporte_status import STATE_ESPERANDO_DETALLES, STATE_INICIO, STATE_PROCESANDO_REPORTE
from paco_rutas import RUTAS_CONOCIDAS
import logging
import threading

load_dotenv()

# Configuración
TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
print(f"Token de Telegram: {TELEGRAM_TOKEN}")

# CAMBIO 1: Corregir la URL del webhook
WEBHOOK_URL = f"https://a084-189-203-88-22.ngrok-free.app/webhook"  # Removido el token de la URL

app = Flask('agente_paco')
bot = telebot.TeleBot(TELEGRAM_TOKEN)

telegramBot = TelegramPaco(
    token=TELEGRAM_TOKEN,
    chat_id=os.environ.get("CHAT_ID"),
    bot=bot
)

logging.basicConfig(level=logging.INFO)

TIPO_REPORTE = [
    "QUEJA",
    "SUGERENCIA",
]

def print_log(message):
    print(message, flush=True)

# CAMBIO 2: Remover ruta conversation innecesaria o corregirla
@app.route('/conversation', methods=['POST'])
def conversation():
    user_input = request.get_json()
    print_log(user_input)
    conversation_id = str(uuid.uuid4())
    print_log(f"Nueva conversación iniciada con el ID: {conversation_id}")
    try:
        if TELEGRAM_TOKEN != "":
            chat_id = user_input['message']['chat']['id']
            query = user_input['message']['text']

        start_time = time.time()
        end_time = time.time()
        print_log(f"Respuesta recibida en {end_time - start_time:.2f} segundos")
    except Exception as e:
        print(f"Error en conversation: {e}")

    return Response("ok", status=200)

# CAMBIO 3: Configurar handlers del bot CORRECTAMENTE
@bot.message_handler(commands=['start'])
def send_welcome(message):
    print_log(f"Nuevo usuario: {message.from_user.id} - {message.from_user.first_name}")
    telegramBot.user_states[message.from_user.id] = STATE_INICIO
    telegramBot.bot.send_message(message.chat.id, "Hola mi nombre es Paco, ¿en qué te puedo ayudar?")

# CAMBIO 4: Handlers de medios ANTES del handler general
@bot.message_handler(content_types=['photo', 'document', 'audio', 'video'])
def handle_media(message):
    telegramBot.bot.send_message(message.chat.id, "Disculpe, solo puedo procesar mensajes de texto. ¿En qué puedo ayudarle?")

# CAMBIO 5: Handler general de mensajes al final
@bot.message_handler(func=lambda message: True)
def handle_message(message):
    try:
        print_log(f"Mensaje recibido: {message.text} de usuario {message.from_user.id}")
        telegramBot.procesar_mensaje(message)
    except Exception as e:
        logging.error(f"Error procesando mensaje: {e}")
        telegramBot.bot.send_message(message.chat.id, "Disculpe, hubo un error. ¿Puede intentar de nuevo?")

# Rutas Flask
@app.route('/')
def index():
    return "Bot RTP Paco está funcionando! 🤖"

# CAMBIO 6: Mejorar el webhook handler
@app.route('/webhook', methods=['POST'])
def webhook():
    try:
        print_log("Webhook recibido")
        json_str = request.get_data().decode('UTF-8')
        print_log(f"Datos recibidos: {json_str}")
        
        update = telebot.types.Update.de_json(json_str)
        bot.process_new_updates([update])
        return jsonify({'status': 'ok'})
    except Exception as e:
        logging.error(f"Error en webhook: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/set_webhook', methods=['GET'])
def set_webhook():
    try:
        # Primero remover webhook existente
        result = telegramBot.bot.remove_webhook()
        print_log(f"Webhook removido: {result}")
        
        # Establecer nuevo webhook
        result = telegramBot.bot.set_webhook(url=WEBHOOK_URL)
        print_log(f"Webhook establecido: {result}")
        
        # Verificar webhook
        webhook_info = telegramBot.bot.get_webhook_info()
        print_log(f"Info del webhook: {webhook_info}")
        
        return jsonify({
            'status': 'webhook set successfully',
            'url': WEBHOOK_URL,
            'webhook_info': {
                'url': webhook_info.url,
                'has_custom_certificate': webhook_info.has_custom_certificate,
                'pending_update_count': webhook_info.pending_update_count
            }
        })
    except Exception as e:
        logging.error(f"Error setting webhook: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/remove_webhook', methods=['GET'])
def remove_webhook():
    try:
        result = telegramBot.bot.remove_webhook()
        return jsonify({'status': 'webhook removed successfully', 'result': result})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# CAMBIO 7: Corregir referencia a user_states
@app.route('/bot_info', methods=['GET'])
def bot_info():
    try:
        me = telegramBot.bot.get_me()
        return jsonify({
            'bot_name': me.first_name,
            'username': me.username,
            'active_users': len(telegramBot.user_states)  # Corregido
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# CAMBIO 8: Corregir referencia a user_states en stats
@app.route('/stats', methods=['GET'])
def stats():
    try:
        return jsonify({
            'active_conversations': len(telegramBot.user_states),
            'states_breakdown': {
                STATE_INICIO: sum(1 for state in telegramBot.user_states.values() if state == STATE_INICIO),
                STATE_ESPERANDO_DETALLES: sum(1 for state in telegramBot.user_states.values() if state == STATE_ESPERANDO_DETALLES),
                STATE_PROCESANDO_REPORTE: sum(1 for state in telegramBot.user_states.values() if state == STATE_PROCESANDO_REPORTE)
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# CAMBIO 9: Endpoint para testing
@app.route('/test', methods=['GET'])
def test():
    return jsonify({
        'status': 'Bot is running',
        'webhook_url': WEBHOOK_URL,
        'timestamp': datetime.now().isoformat()
    })

if __name__ == '__main__':
    print("Bot iniciado...")
    print(f"Webhook URL: {WEBHOOK_URL}")
    print("Presiona Ctrl+C para detener el bot")
    
    # CAMBIO 10: Configurar Flask para producción
    app.run(debug=False, host='0.0.0.0', port=9696, threaded=True)