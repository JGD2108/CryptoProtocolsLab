# Secure Communication Systems with Cryptographic Protocols

Este repositorio implementa tres escenarios de comunicación segura con diferentes protocolos criptográficos, ataques y análisis de eficiencia.

## Requisitos

- Python 3.8+
- Bibliotecas: pycryptodome, pyshark, matplotlib, numpy, pandas, cryptography

Para instalar las dependencias:

```bash
pip install pycryptodome pyshark matplotlib numpy pandas cryptography
```

## Estructura del Proyecto

```
Cripto2/
├── Client.py          # Cliente para todos los escenarios
├── Server.py          # Servidor para todos los escenarios
├── Escenario1.py      # Ataque al escenario 1
├── Escenario3.py      # Análisis de eficiencia
├── parameters.json    # Parámetros para Diffie-Hellman
```

## Escenario 1: Diffie-Hellman en Grupo Cíclico con ChaCha20

### Fundamentos Criptográficos

**Intercambio de claves Diffie-Hellman:**
- Permite que dos partes establezcan un secreto compartido de forma segura sobre un canal inseguro
- Se basa en la complejidad del problema del logaritmo discreto en grupos cíclicos
- Utiliza parámetros públicos compartidos: un primo `p`, un número `q` (orden del subgrupo) y un generador `g`

**ChaCha20:**
- Cifrador de flujo moderno que genera una secuencia pseudoaleatoria usando una clave y un nonce
- Ofrece alto rendimiento y seguridad

**KDF (Argon2id):**
- Función de derivación de claves que convierte el secreto compartido en una clave simétrica
- Resistente a ataques por fuerza bruta y de hardware especializado

### Ejecución

1. Inicia el servidor:
```bash
python Server.py
```
2. Selecciona el Escenario 1 cuando se te solicite
3. Elige uno de los conjuntos de parámetros (1-5)

4. Inicia el cliente:
```bash
python Client.py
```

5. El cliente se conectará automáticamente al servidor y realizará el intercambio Diffie-Hellman

6. Ahora puedes enviar mensajes cifrados con ChaCha20 entre cliente y servidor

### Ataque (Baby-Step Giant-Step)

El ataque implementa el algoritmo "baby-step giant-step" para intentar resolver el problema del logaritmo discreto:

```bash
python Escenario1.py
```

Este algoritmo:
1. Intenta encontrar la clave privada a partir de la clave pública intercambiada
2. Tiene una complejidad de O(√q) tiempo y espacio
3. Si tiene éxito, podrá descifrar los mensajes interceptados

## Escenario 2: Diffie-Hellman en Curva Elíptica P-256 con AES-192

### Fundamentos Criptográficos

**ECDH (Elliptic Curve Diffie-Hellman):**
- Variante de DH que utiliza la aritmética de curvas elípticas
- Mayor seguridad con claves más cortas que el DH tradicional
- Curva P-256: curva estándar NIST de 256 bits
- Las operaciones de punto: adición, duplicación y multiplicación escalar

**AES-192:**
- Cifrado por bloques simétrico con bloques de 128 bits y clave de 192 bits
- Modo CBC (Cipher Block Chaining) que encadena los bloques cifrados
- Requiere un vector de inicialización (IV) aleatorio

### Ejecución

1. Inicia el servidor:
```bash
python Server.py
```
2. Selecciona el Escenario 2 cuando se te solicite

3. Inicia el cliente:
```bash
python Client.py
```

4. El cliente se conectará y realizará el intercambio ECDH con el servidor
5. Los mensajes posteriores se cifrarán usando AES-192 en modo CBC

## Escenario 3: Criptografía Asimétrica con ElGamal

### Fundamentos Criptográficos

**ElGamal:**
- Sistema criptográfico asimétrico basado en el problema del logaritmo discreto
- En esta implementación, se utiliza una versión simplificada basada en:
  - Cifrado: `c = m * k mod p` donde `k` es el secreto compartido
  - Descifrado: `m = c * k^(-1) mod p` donde `k^(-1)` es el inverso multiplicativo de `k`

### Ejecución

1. Inicia el servidor:
```bash
python Server.py
```
2. Selecciona el Escenario 3 cuando se te solicite
3. Elige uno de los conjuntos de parámetros (1-5)

4. Inicia el cliente:
```bash
python Client.py
```

5. El cliente intercambiará claves con el servidor mediante Diffie-Hellman
6. Los mensajes se cifrarán usando el esquema ElGamal simplificado

## Análisis de Eficiencia

Para comparar la eficiencia de los diferentes esquemas de cifrado:

```bash
python Escenario3.py
```

Este script:
1. Analiza archivos PCAP capturados de cada escenario
2. Calcula métricas de tamaño de paquete y bytes por mensaje
3. Genera gráficos comparativos:
   - efficiency_comparison.png: Comparación de tamaño promedio y bytes por mensaje
   - packet_size_distribution.png: Distribución de tamaños de paquetes

### Resultados Esperados

```
scenario  total_bytes  message_count  avg_packet_size  bytes_per_message
0  ChaCha20         1234             19        64.947368          64.947368
1   AES-192         1808             15       120.533333         120.533333
2   ElGamal         2998             11       272.545455         272.545455
```

- ChaCha20: Cifrador más eficiente (~65 bytes/mensaje)
- AES-192: Overhead moderado (~121 bytes/mensaje)
- ElGamal: Mayor overhead (2.26x más grande que AES-192, ~273 bytes/mensaje)

## Captura de Tráfico

Para capturar el tráfico para análisis:

1. Abre Wireshark
2. Filtra con: `tcp.port == 8888`
3. Inicia la captura
4. Ejecuta el escenario deseado
5. Detén la captura
6. Guarda como "EscenarioX.pcap"

## Detalles de Implementación

### Protocolos de Intercambio de Claves

- **Diffie-Hellman Básico** (Escenario 1 y 3):
  ```
  Servidor                    Cliente
     |      "Escenario:X"        |
     |-------------------------->|
     |       "Modo:Y"            |
     |-------------------------->|
     | g^a mod p                 |
     |-------------------------->|
     |                  g^b mod p|
     |<--------------------------|
     | Calcula secreto: (g^b)^a  | Calcula secreto: (g^a)^b
  ```

- **ECDH** (Escenario 2):
  ```
  Servidor                    Cliente
     | Curva P-256, G=(x,y)      |
     | α·G = U                   |
     |-------------------------->|
     |                   β·G = V |
     |<--------------------------|
     | Calcula secreto: α·V      | Calcula secreto: β·U
  ```

### Transformación de Secreto a Clave

En los escenarios 1 y 2, se aplica una función KDF (Argon2id) al secreto compartido:

```python
kdf = Argon2id(
    salt=salt,
    length=32,  # 32 bytes para ChaCha20, 24 bytes para AES-192
    iterations=1,
    lanes=4,
    memory_cost=64 * 1024
)
key = kdf.derive(secreto)
```

En el escenario 3, el secreto compartido se utiliza directamente como clave para ElGamal.

## Notas Importantes

- **Error Común**: Al salir del cliente en el escenario 3, puede aparecer un error WinError 10053 relacionado con la cancelación de la conexión.
- **Captura PCAP**: Asegúrese de capturar solo el tráfico relevante para evitar análisis erróneos.
- **Seguridad**: Esta implementación es educativa y no debe usarse en entornos de producción sin una auditoría adecuada.

## Conclusiones de Eficiencia

1. **Overhead de Cifrado**:
   - ChaCha20: Más eficiente para comunicaciones con ancho de banda limitado
   - AES-192: Balance entre seguridad y overhead
   - ElGamal: Mayor overhead, apropiado cuando se requiere seguridad asimétrica

2. **Rendimiento**:
   - Los esquemas simétricos (ChaCha20, AES-192) son significativamente más eficientes que el asimétrico (ElGamal)
   - ElGamal consume más del doble de ancho de banda que AES-192