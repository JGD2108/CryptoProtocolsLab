import pyshark
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

def analyze_pcap_safely(file_path, scenario_name):
    """Analiza un archivo PCAP con manejo seguro de recursos"""
    total_bytes = 0
    packet_sizes = []
    message_counts = 0
    
    try:
        # Use with statement for proper resource cleanup
        cap = pyshark.FileCapture(file_path)
        for packet in cap:
            if 'TCP' in packet and hasattr(packet, 'tcp'):
                try:
                    if hasattr(packet, 'tcp') and packet.tcp.len != '0':
                        size = int(packet.length)
                        packet_sizes.append(size)
                        total_bytes += size
                        message_counts += 1
                except AttributeError:
                    continue
        # Explicit close
        cap.close()
    except Exception as e:
        print(f"Error procesando {file_path}: {e}")
    
    avg_packet_size = sum(packet_sizes) / len(packet_sizes) if packet_sizes else 0
    
    return {
        'scenario': scenario_name,
        'total_bytes': total_bytes,
        'message_count': message_counts,
        'avg_packet_size': avg_packet_size,
        'packet_sizes': packet_sizes
    }

# Analizar los escenarios
scenario1 = analyze_pcap_safely('Escenario1.pcap', 'ChaCha20')
scenario2 = analyze_pcap_safely('Escenario2.pcap', 'AES-192')
scenario3 = analyze_pcap_safely('Escenario3.pcap', 'ElGamal')

# Crear DataFrame para comparación
scenarios = [scenario1, scenario2, scenario3]
df = pd.DataFrame(scenarios)

# Calcular bytes por mensaje
df['bytes_per_message'] = df['total_bytes'] / df['message_count']

# Mostrar resultados
print(df[['scenario', 'total_bytes', 'message_count', 'avg_packet_size', 'bytes_per_message']])

# Visualizar resultados
plt.figure(figsize=(12, 6))

# Gráfico de barras para tamaño promedio de paquetes
plt.subplot(1, 2, 1)
plt.bar(df['scenario'], df['avg_packet_size'])
plt.title('Tamaño promedio de paquete por escenario')
plt.ylabel('Bytes')

# Gráfico de barras para bytes totales
plt.subplot(1, 2, 2)
plt.bar(df['scenario'], df['bytes_per_message'])
plt.title('Bytes por mensaje por escenario')
plt.ylabel('Bytes/mensaje')

plt.tight_layout()
plt.savefig('efficiency_comparison.png')
plt.show()

# Análisis detallado de la distribución de tamaños de paquetes
plt.figure(figsize=(10, 6))
for scenario in scenarios:
    plt.hist(scenario['packet_sizes'], alpha=0.5, bins=20, 
             label=f"{scenario['scenario']} (media: {scenario['avg_packet_size']:.1f})")
plt.legend()
plt.title('Distribución de tamaños de paquetes')
plt.xlabel('Tamaño del paquete (bytes)')
plt.ylabel('Frecuencia')
plt.savefig('packet_size_distribution.png')
plt.show()