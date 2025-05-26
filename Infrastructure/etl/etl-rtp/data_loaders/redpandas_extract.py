from mage_ai.streaming.sources.base_python import BasePythonSource
from typing import Callable
from kafka import KafkaConsumer
import json

if 'streaming_source' not in globals():
    from mage_ai.data_preparation.decorators import streaming_source


@streaming_source
class CustomSource(BasePythonSource):
    def init_client(self):
        """
        Implement the logic of initializing the client.
        """
        self.consumer = KafkaConsumer(
            'gps_positions',                        # Tópico al que se suscribe
            bootstrap_servers='streaming:19092',     # Dirección del broker Kafka
            auto_offset_reset='earliest',           # Comienza a leer desde el inicio si no hay offset guardado
            group_id='test_gps_group',              # Identificador del grupo de consumidores
            enable_auto_commit=True,                # Se activará el auto commit de offsets
            value_deserializer=lambda m: json.loads(m.decode('utf-8'))  # Deserialización de los mensajes en JSON
        )

    def batch_read(self, handler: Callable):
        """
        Batch read the messages from the source and use handler to process the messages.
        """
        while True:
            records = []
            # Implement the logic of fetching the records
            if len(records) > 0:
                handler(records)
