import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

import numpy as np


class Index:
    """ 
    Un índice de búsqueda simple que utiliza TF-IDF y similitud de coseno para campos de texto y coincidencia exacta para campos de palabras clave.

    Atributos:
    - text_fields (list): Lista de nombres de campos de texto a indexar.
    - keyword_fields (list): Lista de nombres de campos de palabras clave a indexar.
    - vectorizers (dict): Diccionario de instancias de TfidfVectorizer para cada campo de texto.
    - keyword_df (pd.DataFrame): DataFrame que contiene los datos de los campos de palabras clave.
    - text_matrices (dict): Diccionario de matrices TF-IDF para cada campo de texto.
    - docs (list): Lista de documentos indexados.
    """ 

    def __init__(self, text_fields, keyword_fields, vectorizer_params={}):
        """
        Inicializa el índice con los campos de texto y palabras clave especificados. 

        Args:
        - text_fields (list): Lista de nombres de campos de texto a indexar.
        - keyword_fields (list): Lista de nombres de campos de palabras clave a indexar.
        - vectorizer_params (dict): Parámetros opcionales para TfidfVectorizer.
        """
        self.text_fields = text_fields
        self.keyword_fields = keyword_fields

        self.vectorizers = {field: TfidfVectorizer(**vectorizer_params) for field in text_fields}
        self.keyword_df = None
        self.text_matrices = {}
        self.docs = []

    def fit(self, docs):
        """
        Ajusta el índice con los documentos proporcionados.

        Args:
        - docs (list of dict): Lista de documentos a indexar. Cada documento es un diccionario.
        """
        self.docs = docs
        keyword_data = {field: [] for field in self.keyword_fields}

        for field in self.text_fields:
            texts = [doc.get(field, '') for doc in docs]
            self.text_matrices[field] = self.vectorizers[field].fit_transform(texts)

        for doc in docs:
            for field in self.keyword_fields:
                keyword_data[field].append(doc.get(field, ''))

        self.keyword_df = pd.DataFrame(keyword_data)

        return self

    def search(self, query, filter_dict={}, boost_dict={}, num_results=10):
        """
        Busca en el índice con la consulta, filtros y parámetros de impulso proporcionados.

        Args:
        - consulta (str): La cadena de consulta de búsqueda.
        - filtro_dict (dict): Diccionario de campos de palabras clave para filtrar. 
        - impulso_dict (dict): Diccionario de puntajes de impulso para los campos de texto.
        - num_resultados (int): Número de resultados principales a devolver. Por defecto 10.

        Returns:
        - list of dict: Lista de documentos que coinciden con los criterios de búsqueda, ordenados por relevancia.
        """
        query_vecs = {field: self.vectorizers[field].transform([query]) for field in self.text_fields}
        scores = np.zeros(len(self.docs))

        # Compute cosine similarity for each text field and apply boost
        for field, query_vec in query_vecs.items():
            sim = cosine_similarity(query_vec, self.text_matrices[field]).flatten()
            boost = boost_dict.get(field, 1)
            scores += sim * boost

        # Apply keyword filters
        for field, value in filter_dict.items():
            if field in self.keyword_fields:
                mask = self.keyword_df[field] == value
                scores = scores * mask.to_numpy()

        # Use argpartition to get top num_results indices
        top_indices = np.argpartition(scores, -num_results)[-num_results:]
        top_indices = top_indices[np.argsort(-scores[top_indices])]

        # Filter out zero-score results
        top_docs = [self.docs[i] for i in top_indices if scores[i] > 0]

        return top_docs