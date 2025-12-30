# 🔐 Cifrado Simétrico

## Índice
1. [Introducción](#introducción)
2. [Conceptos Clave](#conceptos-clave)
3. [Algoritmos Comunes](#algoritmos-comunes)
4. [Implementación en Java](#implementación-en-java)
5. [Buenas Prácticas](#buenas-prácticas)
6. [Ejemplos de Código](#ejemplos-de-código)

## Introducción

El cifrado simétrico utiliza la **misma clave** tanto para cifrar como para descifrar información. Es más rápido que el cifrado asimétrico y se utiliza comúnmente para cifrar grandes volúmenes de datos.

### ¿Cuándo usar cifrado simétrico?

- Cifrado de archivos locales
- Cifrado de bases de datos
- Comunicación segura donde ambas partes comparten una clave
- Cifrado de sesión (después de intercambiar claves con asimétrico)

## Conceptos Clave

### 1. Clave Simétrica
Una secuencia de bytes que debe mantenerse secreta y compartirse de forma segura entre las partes.

### 2. Vector de Inicialización (IV)
Valor aleatorio que asegura que el mismo texto plano produzca diferentes textos cifrados cada vez.

### 3. Modos de Operación
- **ECB** (Electronic Codebook): ❌ NO USAR - no es seguro
- **CBC** (Cipher Block Chaining): ✅ Seguro, requiere IV
- **GCM** (Galois/Counter Mode): ✅ Recomendado - incluye autenticación
- **CTR** (Counter Mode): ✅ Paralelizable

### 4. Padding
Relleno agregado al texto plano para completar bloques del tamaño requerido.

## Algoritmos Comunes

| Algoritmo | Tamaño de Clave | Seguridad | Velocidad |
|-----------|-----------------|-----------|-----------|
| **AES-256** | 256 bits | Alta | Rápido |
| **AES-128** | 128 bits | Alta | Muy rápido |
| **ChaCha20** | 256 bits | Alta | Muy rápido |
| **DES** | 56 bits | ❌ Obsoleto | Lento |
| **3DES** | 168 bits | ⚠️ Deprecado | Muy lento |

**Recomendación**: Usar **AES-256-GCM** para nuevos proyectos.

## Implementación en Java

Java proporciona la API JCE (Java Cryptography Extension) para operaciones criptográficas.


## Buenas Prácticas

### ✅ HACER

1. **Usar AES-256-GCM** para nuevas implementaciones
2. **Generar claves de forma segura** usando `SecureRandom`
3. **Usar un IV único** por cada operación de cifrado
4. **Nunca hardcodear claves** en el código fuente
5. **Usar derivación de claves** (PBKDF2) cuando se parte de una contraseña
6. **Implementar autenticación** (GCM o HMAC) para detectar manipulación

### ❌ EVITAR

1. **NO usar ECB** - revela patrones en los datos
2. **NO reutilizar IVs** con la misma clave
3. **NO usar algoritmos obsoletos** (DES, RC4)
4. **NO implementar tu propio algoritmo** de cifrado
5. **NO almacenar claves en texto plano**
6. **NO usar claves débiles** o predecibles

## Ejemplos de Código

### Archivos de Ejemplo

- `AESEncryption.java` - Implementación completa de AES-GCM
- `AESExample.java` - Ejemplos de uso básico
- `KeyManagement.java` - Generación y almacenamiento seguro de claves
- `FileEncryption.java` - Cifrado de archivos
- `BadPractices.java` - ⚠️ Ejemplos de lo que NO hacer


## Caso de Uso Real: Cifrado de Datos Sensibles

```java
// Cifrar información de tarjeta de crédito antes de almacenar
String cardNumber = "4532-1234-5678-9010";
byte[] key = KeyManagement.loadOrGenerateKey();
String encrypted = AESEncryption.encrypt(cardNumber, key);

// Guardar 'encrypted' en la base de datos
database.save(encrypted);

// Recuperar y descifrar cuando sea necesario
String encryptedFromDB = database.load();
String decrypted = AESEncryption.decrypt(encryptedFromDB, key);
```

## Referencias

- [NIST Special Publication 800-38D (GCM)](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [Java Cryptography Architecture](https://docs.oracle.com/en/java/javase/17/security/java-cryptography-architecture-jca-reference-guide.html)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

## 🎓 Segui aprendiendo, con estos desafios

1. Modifica `AESExample.java` para usar modo CBC en lugar de GCM.
2. Implementa un sistema de versionado de claves para rotación.
3. Crea un benchmark comparando AES-128 vs AES-256.
4. Implementa cifrado de archivos con progreso para archivos grandes.