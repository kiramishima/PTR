import os
import time
import json
from openai import OpenAI
from elasticsearch import Elasticsearch
from sentence_transformers import SentenceTransformer


ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/v1/")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "ollama")
MODEL_NAME = os.getenv("MODEL_NAME", "multi-qa-MiniLM-L6-cos-v1")
INDEX_NAME = os.getenv("INDEX_NAME", "SUAC_Documents")

es_client = Elasticsearch(ELASTIC_URL)
ollama_client = OpenAI(base_url=OLLAMA_URL, api_key="ollama")
openai_client = OpenAI(api_key=OPENAI_API_KEY)
model = SentenceTransformer(MODEL_NAME)

def elastic_search_hybrid(query):
    vector = model.encode(query)
    knn_query = {
        "field": "vec_tag_text",
        "query_vector": vector,
        "k": 5,
        "num_candidates": 10000,
        "boost": 0.5
    }

    keyword_query = {
        "bool": {
            "must": {
                "multi_match": {
                    "query": query,
                    "fields": ["text", "tag_text", "tag"],
                    "type": "best_fields",
                    "boost": 0.5,
                }
            }
        }
    }

    search_query = {
        "knn": knn_query,
        "query": keyword_query,
        "size": 10,
        "_source": ["key", "text", "tag_text", "tag", "vec_tag_text"],
    }

    es_results = es_client.search(
        index=INDEX_NAME,
        body=search_query
    )

    result_docs = []

    for hit in es_results['hits']['hits']:
        result_docs.append(hit['_source'])

    return result_docs

def build_prompt_check_request_type(query, search_results):
    entry_template = """
    - {tipo}: {solicitud}\n
    """.strip()

    prompt_template = """
    Eres un agente de SACMEX.

    INSTRUCCIONES ESTRICTAS:
    - Analiza cuidadosamente la SOLICITUD
    - Genera ÚNICAMENTE un JSON con dos campos: "tipo_solicitud" y "solicitud"
    - NO incluyas información adicional ni estructuras anidadas
    - El "tipo_solicitud" debe ser UNO de estos: "pregunta", "nuevo_reporte", "status_reporte"
    - La "solicitud" es el texto original del usuario
    - Sin texto adicional, solo el JSON en una línea exacta

    FORMATO REQUERIDO:
    {{"tipo_solicitud": "categoria", "solicitud": "texto_completo"}}

    EJEMPLOS:
    {contexto}

    REGLA PRINCIPAL:
    - Elige ÚNICAMENTE UN tipo de solicitud que coincida EXACTAMENTE
    - Si la solicitud es sobre CÓMO, DÓNDE o INFORMACIÓN para realizar un reporte o cuales son los telefonos o redes sociales, usa "pregunta"
    - Si la solicitud contiene palabras clave como "levantar", "reportar", "fuga", usa "nuevo_reporte"
    - Si la solicitud menciona "estatus" o "reporte" específico, usa "status_reporte"
    - Si no hay coincidencia exacta, usa "otro" por defecto

    SOLICITUD: {solicitud}

    JSON DEFINITIVO:""".strip()

    context = ""
    for doc in search_results:
        context = context + entry_template.format(**doc) + "\n\n"

    return prompt_template.format(solicitud=query, contexto=context).strip()

def build_prompt_categorize(query, search_results):
    entry_template = """
    - {solicitud}\n
    """.strip()

    prompt_template = """
    Eres un clasificador de textos especializado en identificar si un mensaje corresponde a una queja o una sugerencia relacionada con servicios de transporte público.
    
    Definiciones:
    - QUEJA: Texto que reporta un problema específico, denuncia una situación negativa, describe un incidente concreto, o expresa inconformidad por un servicio deficiente. Incluye:

        - Reportes de accidentes o situaciones peligrosas
        - Denuncias de mal uso de espacios públicos
        - Descripción de problemas operativos específicos
        - Situaciones de caos o emergencia

    - SUGERENCIA: Texto que propone mejoras, solicita información sobre servicios, expresa necesidades de manera constructiva, o busca soluciones. Incluye:

        - Solicitudes de mejor frecuencia de servicio
        - Peticiones de intervención para mejorar situaciones
        - Preguntas sobre horarios o rutas
        - Propuestas de optimización

    Ejemplos de referencia:
    - QUEJAS:

        - "El taller Popocatépetl Motors usa el carril del RTP como estacionamiento y extensión de su patio de maniobras, bloquea banquetas y pasos peatonales. Debido a esto es el causante de varios accidentes viales."
        - "Caos en las inmediaciones del metro Chabacano, por suspensión en el servicio de la línea 9 del #MetroCDMX debido a un corto circuito"

    - SUGERENCIAS:

        - "Cada cuánto tiempo salen los RTP para comunicar el surponiente de la ciudad sin buen servicio de transporte concesionado desde metro universidad?"
        - "No hay camiones en Acoxpa, ya tardaron demasiado, gente a pleno sol, pésimo servicio ruta 300-A"

    Formato de respuesta:
    Clasifica el siguiente texto y responde únicamente:

    TIPO: [queja/sugerencia]
    JUSTIFICACIÓN: [Breve explicación de por qué pertenece a esa categoría]

    Texto a clasificar:
    {}""".strip()

    context = ""
    for doc in search_results:
        context = context + entry_template.format(**doc) + "\n\n"

    return prompt_template.format(solicitud=query, contexto=context).strip()


def llm(prompt, model="llama3.2:3b"):
    start_time = time.time()
    response = ollama_client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.7
    )
    answer = response.choices[0].message.content
    tokens = {
        'prompt_tokens': response.usage.prompt_tokens,
        'completion_tokens': response.usage.completion_tokens,
        'total_tokens': response.usage.total_tokens
    }

    end_time = time.time()
    response_time = end_time - start_time

    return answer, tokens, response_time

def get_report_type(query, model_choice, search_type):
    if search_type == 'Vector':
        search_results = elastic_search_hybrid(query)
    else:
        search_results = elastic_search_hybrid(query)

    prompt = build_prompt_check_request_type(query, search_results)
    answer, tokens, response_time = llm(prompt, model_choice)

    return {
        'answer': answer,
        'response_time': response_time,
        'model_used': model_choice,
        'prompt_tokens': tokens['prompt_tokens'],
        'completion_tokens': tokens['completion_tokens'],
        'total_tokens': tokens['total_tokens']
    }

def get_address(query, model_choice, search_type):
    if search_type == 'Vector':
        search_results = elastic_search_hybrid(query)
    else:
        search_results = elastic_search_hybrid(query)

    prompt = build_prompt_categorize(query, search_results)
    answer, tokens, response_time = llm(prompt, model_choice)

    return {
        'answer': answer,
        'response_time': response_time,
        'model_used': model_choice,
        'prompt_tokens': tokens['prompt_tokens'],
        'completion_tokens': tokens['completion_tokens'],
        'total_tokens': tokens['total_tokens']
    }

def get_answer(query, model_choice, search_type):
    if search_type == 'Vector':
        search_results = elastic_search_hybrid(query)
    else:
        search_results = elastic_search_hybrid(query)

    prompt = build_prompt_categorize(query, search_results)
    answer, tokens, response_time = llm(prompt, model_choice)

    return {
        'answer': answer,
        'response_time': response_time,
        'model_used': model_choice,
        'prompt_tokens': tokens['prompt_tokens'],
        'completion_tokens': tokens['completion_tokens'],
        'total_tokens': tokens['total_tokens']
    }