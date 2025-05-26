from flask import Flask, request, jsonify, Response
from dotenv import load_dotenv
import time
import uuid
import os
import requests
from assistant import get_report_type, get_address, get_answer
from db import save_conversation, save_feedback, get_recent_conversations, get_feedback_stats
import telebot
from telebot import types
from datetime import datetime
from utils import generar_mapa_ubicacion, validar_email, validar_telefono
import random

load_dotenv()

TELEGRAM_TOKEN = os.environ.get("TELEGRAM_TOKEN")
print(TELEGRAM_TOKEN)
app = Flask('agente_paco')
bot = telebot.TeleBot(TELEGRAM_TOKEN)
user_states = {}

TIPO_REPORTE = [
    "QUEJA",
    "SUGERENCIA",
]

def print_log(message):
    print(message, flush=True)

@app.route('/conversation', methods=['POST'])
def conversation():
    user_input = request.get_json() # Recibimos los datos
    print_log(user_input)
    conversation_id = str(uuid.uuid4()) # Generamos un id unico de la platica
    model_choice = "llama3.2:3b" # En caso de usar otro modelo LLM aqui podemos indicarlo

    print_log(f"Nueva conversación iniciada con el ID: {conversation_id}")
    topic = user_input['SOLICITUD'] # Indica si la 
    query = user_input["MENSAJE"]
    search_type = "Vector"

    print_log(f"Obteniendo respuesta del asistente utilizando {model_choice} como modelo y tipo de busqueda {search_type}")
    try:
        if TELEGRAM_TOKEN != "":
            chat_id = user_input['message']['chat']['id'] # Id del Chatbot de Telegram
            query = user_input['message']['text'] # Texto enviado desde Telegram

        # Identificamos el tipo de Petición
        start_time = time.time() # Medir el tiempo de inicio
        topic_data = get_report_type(query, model_choice, search_type) # Enviamos los datos al modelo
        print_log(topic_data)
        topic = topic_data['tipo_solicitud'] == 'pregunta'
        end_time = time.time() # Tiempo en que tardo en procesar el agente
        print_log(f"Respuesta recibida en {end_time - start_time:.2f} segundos")

        # Invocamos por tipo de peticion
        output = dict()
        if topic_data['tipo_solicitud'] == 'pregunta':
            start_time = time.time() # Medir el tiempo de inicio
            answer_data = get_answer(query, model_choice, search_type) # Enviamos los datos al modelo
            print_log(topic_data)
            end_time = time.time() # Tiempo en que tardo en procesar el agente
            print_log(f"Respuesta recibida en {end_time - start_time:.2f} segundos")
        elif topic_data['tipo_solicitud'] == 'nuevo_reporte':
            start_time = time.time() # Medir el tiempo de inicio
            answer_data = get_answer(query, model_choice, search_type) # Enviamos los datos al modelo
            print_log(topic_data)
            end_time = time.time() # Tiempo en que tardo en procesar el agente
            print_log(f"Respuesta recibida en {end_time - start_time:.2f} segundos")
        elif topic_data['tipo_solicitud'] == 'nuevo_reporte':
            start_time = time.time() # Medir el tiempo de inicio
            answer_data = get_answer(query, model_choice, search_type) # Enviamos los datos al modelo
            print_log(topic_data)
            end_time = time.time() # Tiempo en que tardo en procesar el agente
            print_log(f"Respuesta recibida en {end_time - start_time:.2f} segundos")
        else:
            print("otro tipo")
            output = {
                'conversation_id': conversation_id,
                'answer': "Lo comunicaremos con usted lo más pronto posible para atender a su respuesta, gracias."
            }

        # Enviamos los datos de respuesta
        if TELEGRAM_TOKEN != '':
            # Invocamos el servicio de Telegram
            url = f'https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage'
            payload = {
                'chat_id': chat_id,
                'text': answer_data['answer']
            }
            r = requests.post(url, json=payload)

            if r.status_code == 200:
                return Response('ok', status=200)
            else:
                return Response('Failed to send message to Telegram', status=500)
        else:
            output = {
                'conversation_id': conversation_id,
                'answer': answer_data['answer']
            }

        # Almacenamos la conversación en la Base de datos
        print_log("Guardando la conversación en la base de datos")
        save_conversation(conversation_id, query, answer_data, topic)
        print_log("Conversación guardada de manera exitosa")

        return jsonify(output)  ## send back the data in json format to the user
    except:
        print("No hay mensaje")

    return Response("ok",status=200)

@bot.message_handler(commands=['estatus_reporte'])
def consultar_estatus_reporte(message):
    """Consultar el estatus de un reporte de fuga"""
    bot.reply_to(message, 
        "Por favor, ingrese el ID de su reporte para consultar su estatus.\n"
        "El ID es un código único que se generó cuando realizó su reporte de fuga."
    )
    # Establecer un estado para esperar el ID del reporte
    user_states[message.from_user.id] = {'stage': 'consulta_estatus'}

# Manejadores de comandos de Telegram
@bot.message_handler(commands=['start'])
def send_welcome(message):
    """Mensaje de bienvenida al iniciar el bot"""
    welcome_text = (
        "Hola !!! Soy el agente Gotin Gotera de Fuga Cero trabajando para la SACMEX 💧\n"
        "Voy ayudarte a reportar fugas de agua, obtener el estatus de tu reporte o responder alguna duda referente al reporte de fugas\n\n"
        "Mis comandos disponibles son:\n"
        "/reportar - Reportar una nueva fuga\n"
        "/estatus_reporte - Consultar estatus de una fuga\n"
        "/consultar - Preguntas frecuentes hacia la SACMEX\n\n"
        "Para reportar, primero comparte tu ubicación GPS 📍"
    )
    bot.reply_to(message, welcome_text)

@bot.message_handler(commands=['reportar'])
def iniciar_reporte(message):
    """Iniciar proceso de reporte de fuga"""
    # Reiniciar el estado del usuario
    user_states[message.from_user.id] = {'stage': 'location'}
    chat_id = message.chat.id

    # Solicitar ubicación GPS
    markup = telebot.types.ReplyKeyboardMarkup(row_width=1, resize_keyboard=True)
    location_button = telebot.types.KeyboardButton("Compartir Ubicación GPS 📍", request_location=True)
    markup.add(location_button)

    # Enviar acción de "typing" 
    bot.send_chat_action(chat_id, 'typing')
    # Enviar el mensaje
    bot.reply_to(message, 
        "Para iniciar un nuevo reporte, puede compartirnos la ubicación GPS 📍 de la fuga\n"
        "Puedes hacerlo presionando el botón o enviando una ubicación directamente.",
        reply_markup=markup
    )

@bot.message_handler(content_types=['location'])
def procesar_ubicacion(message):
    """Procesar la ubicación GPS recibida"""
    user_id = message.from_user.id
    chat_id = message.chat.id

    # Verificar si el usuario está iniciando un reporte
    if user_id not in user_states or user_states[user_id]['stage'] != 'location':
        return

    # Guardar la ubicación en el estado del usuario
    user_states[user_id].update({
        'stage': 'description',
        'latitude': message.location.latitude,
        'longitude': message.location.longitude
    })

    # Enviar acción de "typing" 
    bot.send_chat_action(chat_id, 'typing')
    # Remover teclado anterior
    markup = types.ReplyKeyboardRemove()
    bot.reply_to(message, 
        "Ubicación recibida. Ahora, por favor escribe una descripción de la fuga:",
        reply_markup=markup
    )


@bot.message_handler(func=lambda message: True)
def handle_message(message):
    """Manejar mensajes de texto durante el proceso de reporte"""
    chat_id = message.chat.id
    user_id = message.from_user.id
    print('user_id', user_id)
    
    # Verificar si el usuario está en alguna etapa del proceso de reporte
    if user_id not in user_states:
        return
    
    # Enviar acción de "typing" 
    bot.send_chat_action(chat_id, 'typing')

    # Verificar si el usuario está en el proceso de reportar descripción
    current_stage = user_states[user_id]['stage']
    print('current_stage', current_stage)

    if current_stage == 'description':
        # Obtener los datos almacenados
        # user_state = user_states[user_id]
        
        # Obtener detalles
        descripcion = message.text
        usuario = message.from_user.username or "Anónimo"
        
        # Guardar en base de datos
        leak_id = str(uuid.uuid4())
        print(descripcion, usuario, leak_id)

        user_states[user_id].update({
            'stage': 'nombre',
            'folio': leak_id,
            'descripcion': descripcion,
            'usuario': usuario
        })

        print_log(user_states[user_id])

        bot.reply_to(message, 
            "Antes de terminar\n\n"
            "Por favor, proporciónenos su nombre para que podamos contactarlo una vez que la fuga haya sido reparada:"
        )
        # Limpiar estado del usuario
        # del user_states[user_id]
    elif current_stage == 'nombre':
        # Validar y guardar nombre
        nombre = message.text.strip()
        if len(nombre) < 2:
            bot.reply_to(message, "Por favor, ingresa un nombre válido.")
            return

        user_states[user_id].update({
            'stage': 'telefono',
            'nombre': nombre
        })
        print_log(user_states[user_id])

        bot.reply_to(message, "Gracias. Ahora, me podría proporcinar su número de teléfono a 10 dígitos:")
    elif current_stage == 'telefono':
        # Validar teléfono
        telefono = message.text.strip()
        if not validar_telefono(telefono):
            bot.reply_to(message, "Por favor, ingresa un número de teléfono válido (10 dígitos).")
            return
        
        user_states[user_id].update({
            'stage': 'finalizar',
            'telefono': telefono
        })

        # Obtener los datos almacenados para el reporte final
        user_state = user_states[user_id]

        # Generar mapa
        mapa_buffer = generar_mapa_ubicacion(user_state['latitude'], user_state['longitude'])

        # Respuesta con enlace de Google Maps
        maps_link = f"https://www.google.com/maps?q={user_state['latitude']},{user_state['longitude']}"
        respuesta = (
            f"✅ Fuga reportada exitosamente.\n"
            f"ID de Reporte: {user_state.get('folio', 'N/A')}\n"
            f"Nombre: {user_state.get('nombre', 'No proporcionado')}\n"
            f"Teléfono: {user_state.get('telefono', 'No proporcionado')}\n"
            f"Ubicación: {maps_link}\n"
            f"Descripción: {user_state.get('descripcion', 'No proporcionada')}"
        )
        # bot.reply_to(message, respuesta)
         # Enviar mapa como documento
        bot.send_document(
            message.chat.id,
            mapa_buffer,
            caption=respuesta,
            visible_file_name='ubicacion_fuga.html'
        )
        # Limpiar estado del usuario
        del user_states[user_id]
        return
    elif current_stage == 'consulta_estatus':
        """Procesar la consulta de estatus del reporte"""
        procesar_consulta_estatus(message)
        return

def procesar_consulta_estatus(message):
    """Procesar la consulta de estatus del reporte"""
    user_id = message.from_user.id
    folio_reporte = message.text.strip()

    # Simular consulta de estatus con un estado aleatorio
    estatus = random.choice(ESTATUS_POSIBLES)

    # Generar respuesta
    respuesta = (
        f"🚰 Estado del Reporte 🚱\n"
        f"ID de Reporte: {folio_reporte}\n"
        f"Estado Actual: {estatus}\n\n"
        "Para información más precisa, "
        "por favor contacte a SACMEX directamente."
    )

    # Enviar respuesta
    bot.reply_to(message, respuesta)

    # Limpiar estado del usuario
    del user_states[user_id]

# Rutas de Flask para webhook
@app.route('/' + TELEGRAM_TOKEN, methods=['POST'])
def webhook():
    """Manejar actualizaciones de Telegram"""
    update = telebot.types.Update.de_json(request.stream.read().decode('utf-8'))
    bot.process_new_updates([update])
    return "OK"

@app.route('/set_webhook', methods=['GET'])
def set_webhook():
    """Configurar webhook para el bot"""
    bot.remove_webhook()
    webhook_url = f'https://acd8-187-190-190-71.ngrok-free.app/{TELEGRAM_TOKEN}'
    bot.set_webhook(url=webhook_url)
    return "Webhook configurado exitosamente"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=9696)