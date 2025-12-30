# 🔐 Cifrado Asimétrico (RSA)

## Índice
1. [Introducción](#introducción)
2. [Conceptos Fundamentales](#conceptos-fundamentales)
3. [RSA: Cómo Funciona](#rsa-cómo-funciona)
4. [Casos de Uso](#casos-de-uso)
5. [Implementación en Java](#implementación-en-java)
6. [Buenas Prácticas](#buenas-prácticas)

## Introducción

El cifrado asimétrico utiliza un **par de claves**: una clave pública (puede compartirse libremente y puede ser accesible por cualquiera) y una clave privada (debe mantenerse secreta y solo la conoce el dueno). Lo que se cifra con una clave solo puede descifrarse con la otra.

### Diferencia: Simétrico vs Asimétrico

| Aspecto | Simétrico | Asimétrico |
|---------|-----------|------------|
| **Claves** | 1 clave compartida | Par de claves (pública/privada) |
| **Velocidad** | Muy rápido |  Más lento (10-100x) |
| **Distribución** | Difícil (intercambio seguro) | Fácil (pública se puede compartir) |
| **Tamaño datos** | Ilimitado | Limitado al tamaño de la clave |
| **Uso típico** | Cifrado de datos | Intercambio de claves, firmas |

## Conceptos Fundamentales

### 1. Par de Claves

```
Clave Pública (Public Key)
├─ Se puede compartir libremente
├─ Usada para CIFRAR mensajes
└─ Usada para VERIFICAR firmas

Clave Privada (Private Key)
├─ Debe mantenerse SECRETA
├─ Usada para DESCIFRAR mensajes
└─ Usada para CREAR firmas
```
<p align="center">
 <img src="assets/rsaexample.png" alt="RSA Example" width="300">
</p>


### 2. Dos Operaciones Principales

#### A) Cifrado/Descifrado (Pilar de Confidencialidad)

```
Alice quiere enviar un mensaje secreto a Pepe:

1. Alice obtiene la clave pública de Pepe.
2. Alice cifra el mensaje con la clave pública de Pepe.
3. Alice envía el mensaje cifrado.
4. Pepe descifra con su clave privada.

Resultado: Solo Pepe puede leer el mensaje.
```

#### B) Firma Digital (Pilar de Autenticidad)

```
Alice quiere probar que ella escribió un mensaje:

1. Alice crea un hash del mensaje.
2. Alice firma el hash con su clave privada.
3. Alice envía mensaje + firma.
4. Pepe verifica la firma con la clave pública de Alice.

Resultado: Pepe confirma que Alice escribió el mensaje.
```

## RSA: Cómo Funciona

### Matemáticas Básicas

RSA se basa en la dificultad de factorizar números grandes:

```
1. Elegir dos primos grandes: p y q
2. Calcular n = p × q (módulo)
3. Calcular φ(n) = (p-1) × (q-1)
4. Elegir e tal que 1 < e < φ(n) y gcd(e, φ(n)) = 1
5. Calcular d tal que d × e ≡ 1 (mod φ(n))

Clave Pública: (n, e)
Clave Privada: (n, d)

Cifrar: c = m^e mod n
Descifrar: m = c^d mod n
```

### Tamaños de Clave

| Tamaño | Seguridad | Uso |
|--------|-----------|-----|
| **1024 bits** | Inseguro | NO USAR (deprecado) |
| **2048 bits** | Adecuado | Mínimo recomendado actual |
| **3072 bits** | Alto | Recomendado para datos sensibles |
| **4096 bits** | Extrema | Máxima seguridad (más lento) |

**Recomendación NIST 2024**: Mínimo 2048 bits, preferiblemente 3072+

## Casos de Uso

### ✅ Cuándo Usar RSA

1. **Intercambio de claves simétricas**
   - Cifrar una clave AES para transmitirla.
   - Después usar AES para los datos (híbrido).

2. **Firmas digitales**
   - Autenticar documentos.
   - Verificar integridad de software.
   - Autenticación de APIs.

3. **Certificados SSL/TLS**
   - HTTPS usa RSA (o ECDSA) para establecer conexión.

4. **Autenticación SSH**
   - Claves públicas para login sin contraseña.

### ❌ Cuándo NO Usar RSA

1. **Cifrar grandes volúmenes de datos**
   - Muy lento comparado con AES.
   - Limitado por tamaño de clave.
   - Usar híbrido: RSA + AES.

2. **Aplicaciones de baja latencia**
   - Operaciones costosas computacionalmente.
   - Considerar ECDSA/EdDSA para firmas.

3. **Dispositivos con recursos limitados**
   - IoT puede preferir curvas elípticas (ECC).

## Implementación en Java

### API de Java

Java proporciona soporte nativo para RSA a través de JCA (Java Cryptography Architecture):

```java
// Clases principales
KeyPairGenerator  // Generar pares de claves
Cipher            // Cifrar/descifrar
Signature         // Firmar/verificar
KeyFactory        // Convertir claves
```

### Esquemas de Padding

| Esquema | Seguridad | Uso |
|---------|-----------|-----|
| **OAEP** | Alta | Cifrado (RECOMENDADO) |
| **PSS** | Alta | Firmas (RECOMENDADO) |
| **PKCS1** | Vulnerable | Legacy (evitar si es posible) |
| **NoPadding** | Inseguro | NUNCA USAR |

```java
// Cifrado moderno
Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

// Cifrado legacy (vulnerable a padding oracle)
Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
```

## Buenas Prácticas

### ✅ QUE HACER

1. **Usar claves de 2048 bits mínimo** (preferentemente 3072 o 4096).
2. **OAEP para cifrado**, PSS para firmas.
3. **Cifrado híbrido**: RSA para clave + AES para datos.
4. **Proteger la clave privada**:
   - Cifrarla con contraseña.
   - Almacenar en keystore.
   - Permisos de archivo restrictivos.
5. **Rotar claves periódicamente**: Cada 1-2 años aprox.
6. **Usar SecureRandom** para generación de claves.
7. **Verificar certificados** en cadenas de confianza.

### ❌ QUE NO HACER

1. **NO usar claves de 1024 bits** (factorizables).
2. **NO usar RSA sin padding** (textbook RSA es inseguro).
3. **NO cifrar datos grandes directamente** con RSA.
4. **NO reutilizar claves** entre entornos (dev/prod).
5. **NO transmitir claves privadas** por red.
6. **NO hardcodear claves** en código fuente ni subirlas a un repositorio privado o publico.
7. **NO usar "RSA" sin especificar modo/padding** (defaults inseguros).

## Formato de Claves

### PEM (Privacy Enhanced Mail) este formato luce asi

```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----

-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...
-----END PRIVATE KEY-----
```

### DER (Distinguished Encoding Rules)

Formato binario, más compacto que PEM.

### PKCS#8 vs PKCS#1

- **PKCS#8**: Formato estándar para claves privadas (RECOMENDADO).
- **PKCS#1**: Formato específico de RSA (legacy).

## Limitaciones de Tamaño

### Tamaño Máximo de Datos

```
Tamaño máximo = (tamaño_clave_en_bytes) - padding_overhead

RSA 2048 con OAEP (SHA-256):
= 256 bytes - 66 bytes = 190 bytes máximo

RSA 4096 con OAEP (SHA-256):
= 512 bytes - 66 bytes = 446 bytes máximo
```

**Solución**: Cifrado híbrido

## Cifrado Híbrido (Recomendado)

```
1. Generar clave AES aleatoria (256 bits).
2. Cifrar datos con AES-GCM (rápido, sin límite de tamaño).
3. Cifrar la clave AES con RSA (pequeña, cabe perfectamente).
4. Transmitir: clave_AES_cifrada + datos_cifrados_con_AES.
```

Ventajas:
- Velocidad de AES.
- Seguridad de RSA para intercambio de claves.
- Sin limitaciones de tamaño.

## Comparación con Alternativas

### RSA vs ECC (Elliptic Curve Cryptography)

| Aspecto | RSA 3072 | ECC 256 |
|---------|----------|---------|
| **Seguridad** | Equivalente | Equivalente |
| **Tamaño clave** | 3072 bits | 256 bits |
| **Velocidad firma** | Lenta | Rapida |
| **Velocidad verificación** | Media | Media |
| **Adopción** | Universal | Creciente |
| **Patentes** | Libre | Algunos algoritmos |

**Conclusión**: ECC es el futuro, pero RSA sigue siendo estándar actual. Cabe aclarar que se vera con la computacion cuantica, si sigue siendo suficiente.

## Ejemplos de Código

### Archivos Incluidos

- `RSAEncryption.java` - Implementación completa de RSA
- `RSAKeyManager.java` - Generación y gestión de claves
- `HybridEncryption.java` - Cifrado híbrido RSA+AES
- `DigitalSignature.java` - Firmas digitales con RSA
- `RSAExample.java` - Ejemplos de uso
- `InsecureRSA.java` - ⚠️ Ejemplos de prácticas inseguras


## Caso de Uso Real: Mensajería Segura

```java
// Alice quiere enviar mensaje a Pepe

// 1. Pepe genera su par de claves
KeyPair bobKeys = RSAKeyManager.generateKeyPair(2048);
PublicKey bobPublic = bobKeys.getPublic();

// 2. Pepe comparte su clave pública (puede ser por canal inseguro)
String bobPublicKeyStr = RSAKeyManager.publicKeyToString(bobPublic);

// 3. Alice cifra el mensaje con la clave pública de Pepe
String message = "Información confidencial";
String encrypted = RSAEncryption.encrypt(message, bobPublic);

// 4. Alice envía el mensaje cifrado (puede ser interceptado, no importa)
sendOverNetwork(encrypted);

// 5. Pepe descifra con su clave privada
PrivateKey bobPrivate = bobKeys.getPrivate();
String decrypted = RSAEncryption.decrypt(encrypted, bobPrivate);
```



## Referencias

- [NIST SP 800-56B: Recommendation for Pair-Wise Key-Establishment](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br2.pdf)
- [RFC 8017: PKCS #1: RSA Cryptography Specifications](https://tools.ietf.org/html/rfc8017)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Java Cryptography Architecture Guide](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)

## 🎓 Segui aprendiendo

1. Implementa un sistema de mensajería cifrada entre dos usuarios.
2. Crea un programa que firme y verifique archivos.
3. Compara rendimiento: RSA 2048 vs 4096 bits.
4. Implementa exportación/importación de claves en formato PEM.
5. Crea un sistema de cifrado híbrido para archivos grandes.
6. Implementa rotación automática de claves con período configurable.