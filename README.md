# Analyzing TCPDUMP log

Vamos a analizar un log el cual se nos ha proporcionado en el curso y se incluye dentro de este repositorio, para ello hemos de identificar puertos, protocolos y origen y destino(Se ha añadido un documento acerca de como leer los logs).

## Reporte de Incidente de Seguridad

### Sección 1: Identificar el Protocolo de Red Involucrado en el Incidente

**Protocolos de Red Identificados:**

1. **Protocolo DNS (Domain Name System):**

   - Este protocolo se utiliza para traducir nombres de dominio (por ejemplo, yummyrecipesforme.com, greatrecipesforme.com) en direcciones IP.

   - Ejemplo del log:

     ```bash
     14:18:32.192571 IP your.machine.52444 > dns.google.domain: 35084+ A? yummyrecipesforme.com. (24)
     14:18:32.204388 IP dns.google.domain > your.machine.52444: 35084 1/0/0 A 203.0.113.22 (40)
     ```

2. **Protocolo TCP (Transmission Control Protocol):**

   - Este protocolo se utiliza para establecer conexiones y transferir datos de manera confiable.

   - Ejemplo del log:

     ```bash
     14:18:36.786501 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [S], seq 2873951608, win 65495, options [mss 65495,sackOK,TS val 3302576859 ecr 0,nop,wscale 7], length 0
     14:18:36.786517 IP yummyrecipesforme.com.http > your.machine.36086: Flags [S.], seq 3984334959, ack 2873951609, win 65483, options [mss 65495,sackOK,TS val 3302576859 ecr 3302576859,nop,wscale 7], length 0
     ```

3. **Protocolo HTTP (Hypertext Transfer Protocol):**

   - Este protocolo se utiliza para transferir solicitudes y datos de hipertexto en la web.

   - Ejemplo del log:

     ```bash
     14:18:36.786589 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [P.], seq 1:74, ack 1, win 512, options [nop,nop,TS val 3302576859 ecr 3302576859], length 73: HTTP: GET / HTTP/1.1
     ```

Probablemente aquí se encuentra el problema, vemos bastantes iguales

### Sección 2: Documentar el Incidente

**Detalles del Incidente:**

1. **Solicitudes y Respuestas DNS:**

   - **Solicitud DNS:**

     ```
     14:18:32.192571 IP your.machine.52444 > dns.google.domain: 35084+ A? yummyrecipesforme.com. (24)
     ```

     Esta línea indica que la máquina (IP: your.machine) está consultando el servidor DNS de Google (dns.google) para resolver el dominio "yummyrecipesforme.com".

   - **Respuesta DNS:**

     ```
     14:18:32.204388 IP dns.google.domain > your.machine.52444: 35084 1/0/0 A 203.0.113.22 (40)
     ```

     El servidor DNS responde con la dirección IP "203.0.113.22" para "yummyrecipesforme.com".

2. **Intercambio de TCP:**

   - **Paquete SYN:**

     ```
     14:18:36.786501 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [S], seq 2873951608, win 65495, options [mss 65495,sackOK,TS val 3302576859 ecr 0,nop,wscale 7], length 0
     ```

     La máquina inicia una conexión TCP con "yummyrecipesforme.com" en el puerto 80 (HTTP) con un paquete SYN.

   - **Paquete SYN-ACK:**

     ```
     14:18:36.786517 IP yummyrecipesforme.com.http > your.machine.36086: Flags [S.], seq 3984334959, ack 2873951609, win 65483, options [mss 65495,sackOK,TS val 3302576859 ecr 3302576859,nop,wscale 7], length 0
     ```

     El servidor responde con un paquete SYN-ACK, reconociendo la solicitud.

   - **Paquete ACK:**

     ```
     14:18:36.786529 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [.], ack 1, win 512, options [nop,nop,TS val 3302576859 ecr 3302576859], length 0
     ```

     La máquina envía un paquete ACK para establecer la conexión.

3. **Solicitud HTTP:**

   - Solicitud HTTP GET:

     ```
     14:18:36.786589 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [P.], seq 1:74, ack 1, win 512, options [nop,nop,TS val 3302576859 ecr 3302576859], length 73: HTTP: GET / HTTP/1.1
     ```

     La máquina solicita la página raíz ("/") de "yummyrecipesforme.com" utilizando el método HTTP GET.

**Observación:**

- El patrón de solicitudes DNS y tráfico HTTP se repite para otro dominio, "greatrecipesforme.com".
- Se observa un tráfico significativo en el puerto 80 (HTTP) para ambos dominios.
- La repetición constante de solicitudes HTTP GET y el tráfico intenso pueden ser indicativos de un ataque de fuerza bruta.

Como vemos se repite mas de una vez:

```bash
14:18:36.786501 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [S], seq 2873951608, win 65495, options [mss 65495,sackOK,TS val 3302576859 ecr 0,nop,wscale 7], length 0
14:18:36.786517 IP yummyrecipesforme.com.http > your.machine.36086: Flags [S.], seq 3984334959, ack 2873951609, win 65483, options [mss 65495,sackOK,TS val 3302576859 ecr 3302576859,nop,wscale 7], length 0
14:18:36.786529 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [.], ack 1, win 512, options [nop,nop,TS val 3302576859 ecr 3302576859], length 0
14:18:36.786589 IP your.machine.36086 > yummyrecipesforme.com.http: Flags [P.], seq 1:74, ack 1, win 512, options [nop,nop,TS val 3302576859 ecr 3302576859], length 73: HTTP: GET / HTTP/1.1
14:18:36.786595 IP yummyrecipesforme.com.http > your.machine.36086: Flags [.], ack 74, win 512, options [nop,nop,TS val 3302576859 ecr 330257
```



Un ataque de fuerza bruta se caracteriza por un volumen elevado y repetitivo de solicitudes de conexión a un servido. En este log, la máquina "your.machine" realiza numerosas solicitudes DNS seguidas de conexiones TCP y solicitudes HTTP GET, lo cual es consistente con un comportamiento de ataque de fuerza bruta.



**Recomendación de Remediación:**

- **Uso de Firewalls de Aplicaciones Web (WAF):** Configurar un WAF para detectar y bloquear solicitudes excesivas de una sola dirección IP.
- **Limitación de Tasa a Nivel de Aplicación:** Implementar limitación de tasa en el código de la aplicación para limitar el número de intentos de inicio de sesión u otras acciones críticas que un usuario puede realizar dentro de un período determinado.
- **Limitación de Tasa a Nivel de Red:** Configurar limitación de tasa en dispositivos de red (como enrutadores o balanceadores de carga) para restringir la tasa de tráfico entrante.

