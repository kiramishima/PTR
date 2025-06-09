
from uuid_extensions import uuid7, uuid7str
from reporte_status import STATE_ESPERANDO_DETALLES, STATE_INICIO, STATE_PROCESANDO_REPORTE
from paco_rutas import RUTAS_CONOCIDAS
import re
import telebot

class TelegramPaco:
    def __init__(self, token: str, chat_id: str, bot: telebot.TeleBot):
        self.bot = bot
        self.token = token
        self.chat_id = chat_id
        self.user_states = {}  # Diccionario para almacenar el estado de cada usuario

    def generar_uuid_v7(self):
        """Genera un UUID v7 (basado en tiempo)"""
        return str(uuid7())

    def detectar_tipo_mensaje(self, texto):
        """Detecta si el mensaje es un reporte o una sugerencia"""
        palabras_reporte = ["reporte", "problema", "tardaron", "pesimo", "mal servicio", "no llegan"]
        palabras_sugerencia = ["sugerencia", "ayudo", "mejorar", "accesible", "gracias por"]
        
        texto_lower = texto.lower()
        
        for palabra in palabras_reporte:
            if palabra in texto_lower:
                return "reporte"
        
        for palabra in palabras_sugerencia:
            if palabra in texto_lower:
                return "sugerencia"
        
        return "reporte"  # Por defecto asume reporte

    def extraer_ruta(self, texto):
        """Extrae el número de ruta del texto"""
        for ruta in RUTAS_CONOCIDAS:
            if ruta in texto.upper():
                return ruta
        
        # Buscar patrones como "ruta XX" o "XX-A"
        patron_ruta = re.search(r'ruta\s*(\d+[-A-Z]*)', texto.upper())
        if patron_ruta:
            return patron_ruta.group(1)
        
        patron_numero = re.search(r'(\d+[-A-Z]*)', texto)
        if patron_numero:
            return patron_numero.group(1)
        
        return None

    def generar_respuesta_reporte(self, texto):
        """Genera una respuesta específica basada en el contenido del reporte"""
        texto_lower = texto.lower()
        ruta = self.extraer_ruta(texto)
        
        if "tardaron" in texto_lower or "no llegan" in texto_lower:
            if ruta:
                return f"Entiendo la situación, en este momento las unidades de la ruta {ruta} avanzan lento por un problema vial en su ruta, le recomendamos tomar otras rutas alternas."
            else:
                return "Entiendo la situación, en este momento hay retrasos en el servicio por problemas viales, le recomendamos tomar rutas alternas."
        
        elif "pesimo" in texto_lower or "mal" in texto_lower:
            return "Lamentamos los inconvenientes ocasionados, tomaremos en cuenta su reporte para mejorar nuestro servicio."
        
        elif "conductor" in texto_lower:
            return "Tomaremos nota de la situación con el personal operativo para las medidas correspondientes."
        
        else:
            return "Hemos registrado su reporte y será atendido por el área correspondiente."

    def procesar_mensaje(self, message):
        """Procesa los mensajes del bot"""
        user_id = message.from_user.id
        texto = message.text
        
        # Si no hay estado, inicializar
        if user_id not in self.user_states:
            self.user_states[user_id] = STATE_INICIO
            self.bot.send_message(message.chat.id, "Hola mi nombre es Paco, ¿en qué te puedo ayudar?")
            return
        
        estado_actual = self.user_states[user_id]
        
        if estado_actual == STATE_INICIO:
            # Detectar si quiere levantar un reporte
            if "reporte" in texto.lower():
                self.user_states[user_id] = STATE_ESPERANDO_DETALLES
                self.bot.send_message(message.chat.id, "Comprendo, me puede dar detalles de su reporte hacia el RTP, por favor :D")
            else:
                # Detectar tipo de mensaje (reporte o sugerencia)
                tipo = self.detectar_tipo_mensaje(texto)
                
                if tipo == "sugerencia":
                    self.bot.send_message(message.chat.id, "Comprendo, tomaremos en cuenta sus sugerencias para seguir mejorando nuestro servicio 🚌 ¿Hay algo más en lo que le puedo ayudar?")
                    self.user_states[user_id] = STATE_INICIO
                else:
                    # Tratar como reporte directo
                    self.user_states[user_id] = STATE_PROCESANDO_REPORTE
                    respuesta = self.generar_respuesta_reporte(texto)
                    self.bot.send_message(message.chat.id, respuesta)
        
        elif estado_actual == STATE_ESPERANDO_DETALLES:
            # Procesar los detalles del reporte
            respuesta = self.generar_respuesta_reporte(texto)
            self.bot.send_message(message.chat.id, respuesta)
            self.user_states[user_id] = STATE_PROCESANDO_REPORTE
        
        elif estado_actual == STATE_PROCESANDO_REPORTE:
            # Respuestas a confirmaciones o agradecimientos
            texto_lower = texto.lower()
            
            if any(palabra in texto_lower for palabra in ["ok", "gracias", "entiendo", "comprendo"]):
                codigo_reporte = self.generar_uuid_v7()
                respuesta = f"De nada, espero haberte ayudado, su ID de reporte es **RTP-{codigo_reporte}**, con este ID podrá dar seguimiento a su reporte. ¿Hay algo más en lo que le puedo ayudar?"
                self.bot.send_message(message.chat.id, respuesta, parse_mode='Markdown')
                self.user_states[user_id] = STATE_INICIO
            else:
                # Continuar conversación
                self.bot.send_message(message.chat.id, "¿Hay algo más en lo que le puedo ayudar?")
        
        # Manejar despedidas en cualquier momento
        if any(palabra in texto.lower() for palabra in ["no es todo", "no, es todo", "nada mas", "eso es todo"]):
            self.bot.send_message(message.chat.id, "Me despido que tenga un buen día 🤖")
            self.user_states[user_id] = STATE_INICIO