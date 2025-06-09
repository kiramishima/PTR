import folium
import io

def generar_mapa_ubicacion(latitud, longitud):
    """Generar mapa HTML con marcador de ubicación"""
    mapa = folium.Map(location=[latitud, longitud], zoom_start=16)
    
    # Añadir marcador de fuga
    folium.Marker(
        [latitud, longitud], 
        popup='Ubicación de Fuga',
        icon=folium.Icon(color='red', icon='water', prefix='fa')
    ).add_to(mapa)
    
    # Guardar mapa en un archivo temporal en memoria
    mapa_buffer = io.BytesIO()
    mapa.save(mapa_buffer, close_file=False)
    mapa_buffer.seek(0)
    
    return mapa_buffer

def validar_email(email):
    """Validar formato de correo electrónico"""
    patron = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron, email) is not None

def validar_telefono(telefono):
    """Validar formato de teléfono (solo números, 10 dígitos)"""
    return telefono.isdigit() and len(telefono) == 10

