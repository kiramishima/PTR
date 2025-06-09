import os
import pandas as pd
import json
from sentence_transformers import SentenceTransformer
from elasticsearch import Elasticsearch
from tqdm.auto import tqdm
from dotenv import load_dotenv
from pathlib import Path
from typing import List
from ingest import ingest_data, load_index
import telebot

load_dotenv()

ELASTIC_URL = os.getenv("ELASTIC_URL_LOCAL", "http://localhost:9200")
MODEL_NAME = os.getenv("MODEL_NAME", "multi-qa-MiniLM-L6-cos-v1")
INDEX_NAME = os.getenv("INDEX_NAME", "RTP_Documents")
FILE_DIR = os.getenv("DOCS_DIR", "./documents")

def load_model():
    print(f"Loading model: {MODEL_NAME}")
    return SentenceTransformer(MODEL_NAME)


def setup_elasticsearch():
    print("Setting up Elasticsearch...")
    es_client = Elasticsearch(ELASTIC_URL)
    
    index_settings = {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0
        },
        "mappings": {
            "properties":
                {
                    'key': {"type": "keyword"},
                    'text': {"type": "text"},
                    'tag': {"type": "text"},
                    'text_tag': {"type": "text"},
                    'text_vector': {"type": "dense_vector", "dims": 768, "index": True, "similarity": "cosine"},
                    'text_tag_vector': {"type": "dense_vector", "dims": 768, "index": True, "similarity": "cosine"}
                }
        }
    }

    es_client.indices.delete(index=INDEX_NAME, ignore_unavailable=True)
    es_client.indices.create(index=INDEX_NAME, body=index_settings)
    print(f"Elasticsearch index '{INDEX_NAME}' created")
    return es_client


def load_documents(es_client, documents, model):
    print("Cargando documentos...")
    operations = []
    for doc in tqdm(documents):
        doc["text_vector"] = model.encode(doc["text"]).tolist()
        text_tag = f"{doc["text"]} {doc["tag"]}"
        doc["text_tag_vector"] = model.encode(text_tag).tolist()
        operations.append(doc)

    for doc in tqdm(operations):
        try:
            es_client.index(index=INDEX_NAME, document=doc)
        except Exception as e:
            print(e)

    print(f"Se cargarón {len(operations)} documentos")


def main():
    print("Iniciando proceso de indexado...")

    documents = ingest_data() # Carga los datos de DATASETS
    ground_truth = ingest_data("../DATASETS/ground-truth-retrieval_llama3_2_3b.csv")
    model = load_model() # Carga el modelo del Transformer
    es_client = setup_elasticsearch() # Crea un cliente hacia ElasticSearch
    load_documents(es_client, documents, model)

    print("Proceso de indexado de documentos realizado completamente!")


if __name__ == "__main__":
    main()