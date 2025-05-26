from kafka import KafkaProducer
import json
import time

def create_kafka_producer(bootstrap_servers='localhost:9092'):
    """
    Crea y retorna un KafkaProducer configurado para serializar mensajes en JSON.
    """
    producer = KafkaProducer(
        bootstrap_servers=bootstrap_servers,
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )
    return producer

def interpolate_coords(start, end, steps):
    """
    Genera una lista de coordenadas intermedias entre 'start' y 'end'.
    
    Parámetros:
      - start: tupla (latitud, longitud) punto de inicio.
      - end: tupla (latitud, longitud) punto final.
      - steps: cantidad de pasos para dividir el trayecto.
      
    Retorna:
      - Lista de tuplas (lat, lon) incluyendo inicio y fin.
    """
    lat_start, lon_start = start
    lat_end, lon_end = end
    coords = []
    for i in range(steps + 1):
        lat = lat_start + (lat_end - lat_start) * i / steps
        lon = lon_start + (lon_end - lon_start) * i / steps
        coords.append((lat, lon))
    return coords

def send_positions(producer, topic, coords, sleep_time=1):
    """
    Envía cada coordenada de la lista 'coords' a Kafka con una pausa especificada.
    
    Parámetros:
      - producer: instancia de KafkaProducer.
      - topic: tópico de Kafka en donde se publican los mensajes.
      - coords: lista de coordenadas (lat, lon) a enviar.
      - sleep_time: tiempo en segundos entre envíos.
    """
    for (lat, lon) in coords:
        message = {
            "ruta": "17E",
            "modulo": 4,
            "latitude": lat,
            "longitude": lon,
            "timestamp": time.time()  # marca de tiempo UNIX
        }
        producer.send(topic, value=message)
        print(f"Mensaje enviado: {message}")
        time.sleep(sleep_time)

def main():
    # Configuración de Kafka
    bootstrap_servers = 'localhost:19092'
    topic = 'gps_positions'
    
    # Coordenadas de inicio y fin:
    # Estadio Azteca (aproximadamente)
    estadio_azteca = (19.302087, -99.150085)
    # Ciudad Universitaria de la UNAM (aproximadamente)
    ciudad_universitaria = (19.332200, -99.188200)
    
    # Número de pasos para simular el recorrido (entre inicio y fin)
    steps = 10  # esto generará 11 puntos en total
    
    # Generamos las coordenadas intermedias
    coords = interpolate_coords(estadio_azteca, ciudad_universitaria, steps)
    print(coords)
    # Creamos el productor de Kafka
    producer = create_kafka_producer(bootstrap_servers=bootstrap_servers)
    
    # Enviamos las posiciones a Kafka
    send_positions(producer, topic, coords, sleep_time=2)  # 2 segundos de pausa entre mensajes
    
    # Aseguramos el envío y cerramos el productor
    producer.flush()
    producer.close()

if __name__ == '__main__':
    main()
