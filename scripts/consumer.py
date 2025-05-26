from kafka import KafkaConsumer
import json

def main():
    # Configura el consumidor de Kafka
    consumer = KafkaConsumer(
        'gps_positions',                        # Tópico al que se suscribe
        bootstrap_servers='localhost:19092',     # Dirección del broker Kafka
        auto_offset_reset='earliest',           # Comienza a leer desde el inicio si no hay offset guardado
        group_id='test_gps_group',              # Identificador del grupo de consumidores
        enable_auto_commit=True,                # Se activará el auto commit de offsets
        value_deserializer=lambda m: json.loads(m.decode('utf-8'))  # Deserialización de los mensajes en JSON
    )

    print("Consumer iniciado. Esperando mensajes...")

    try:
        # Bucle para leer los mensajes a medida que llegan
        for message in consumer:
            print("Mensaje recibido:", message.value)
    except KeyboardInterrupt:
        print("Interrupción manual. Cerrando consumer...")
    finally:
        consumer.close()

if __name__ == '__main__':
    main()
