# 🔐 Autenticación

## Contenido
1. [¿Qué es la Autenticación?](#qué-es-la-autenticación)
2. [Diferencia: Autenticación vs Autorización](#diferencia-autenticación-vs-autorización)
3. [Tipos de Autenticación](#tipos-de-autenticación)
4. [Factores de Autenticación](#factores-de-autenticación)
5. [Métodos de Autenticación](#métodos-de-autenticación)
7. [Buenas Prácticas](#buenas-prácticas)

## ¿Qué es la Autenticación?

**Autenticación** es el proceso de **verificar la identidad** de un usuario, sistema o entidad.

Es la respuesta a esta pregunta clave. > **Pregunta clave**: "¿Quién eres?"

### Analogía del Mundo Real

```
Aeropuerto → Mostrador de Check-in
├─ Te piden tu pasaporte.
├─ Verifican que la foto coincida con tu cara.
├─ Confirman que el nombre en el ticket coincida con el pasaporte.
└─ Resultado: "Sí, vos sos Pepe Pérez".

Esto es AUTENTICACIÓN → Verificar tu identidad.
```

## Diferencia: Autenticación vs Autorización

| Aspecto | Autenticación | Autorización |
|---------|---------------|--------------|
| **Pregunta** | ¿Quién eres? | ¿Qué podes hacer? |
| **Propósito** | Verificar identidad | Verificar permisos |
| **Cuándo ocurre** | Primero (login) | Después (cada acción) |
| **Ejemplo** | Usuario + contraseña | Acceso a recursos, paneles, etc |
| **Resultado** | Identidad confirmada | Permiso otorgado/denegado |

## Tipos de Autenticación

### 1. Autenticación de Usuario (Más Común)

Verificar que un humano es quien dice ser.

```java
// Ejemplo básico
public boolean authenticateUser(String username, String password) {
    User user = database.findByUsername(username);
    
    if (user == null) {
        return false; // Usuario no existe
    }
    
    // Verificar contraseña hasheada
    return PasswordHashing.verify(password, user.passwordHash);
}
```

### 2. Autenticación de Sistema/Servicio

Verificar que un sistema/API es legítimo.

```java
// API Key Authentication
public boolean authenticateService(String apiKey) {
    return validApiKeys.contains(apiKey);
}

// OAuth Client Credentials
public boolean authenticateClient(String clientId, String clientSecret) {
    Client client = database.findByClientId(clientId);
    return client != null && client.secret.equals(clientSecret);
}
```

### 3. Autenticación de Dispositivo

Verificar que un dispositivo es reconocido/autorizado.

```java
// Device Fingerprint
public boolean authenticateDevice(String deviceId, String fingerprint) {
    Device device = database.findByDeviceId(deviceId);
    return device != null && device.fingerprint.equals(fingerprint);
}
```

## Factores de Autenticación

### Tres Categorías de Factores

```
1. Algo que SABES (Knowledge Factor)
   └─ Contraseña, PIN, respuesta secreta.

2. Algo que TENES (Possession Factor)
   └─ Teléfono, token, tarjeta inteligente.

3. Algo que ERES (Inherence Factor)
   └─ Huella dactilar, reconocimiento facial.
```

### Single-Factor Authentication (SFA)

Usa **un solo** factor.

```java
// Ejemplo: Solo contraseña
public class SingleFactorAuth {
    public boolean authenticate(String username, String password) {
        User user = getUserFromDB(username);
        
        if (user == null) {
            return false;
        }
        
        // Solo verificamos contraseña (1 factor)
        return PasswordHashing.verify(password, user.passwordHash);
    }
}
```

**Problema**: Si la contraseña se compromete, la cuenta queda expuesta.

### Multi-Factor Authentication (MFA/2FA)

Usa **dos o más** factores de diferentes categorías.

```java
// Ejemplo: Contraseña + Código SMS (2FA)
public class TwoFactorAuth {
    
    // Paso 1: Verificar contraseña (algo que SABES)
    public String initiateLogin(String username, String password) {
        User user = getUserFromDB(username);
        
        if (user == null || !PasswordHashing.verify(password, user.passwordHash)) {
            throw new AuthenticationException("Credenciales inválidas");
        }
        
        // Generar y enviar código
        String code = generateRandomCode(6);
        sendSMS(user.phone, "Tu código es: " + code);
        
        // Guardar código temporalmente
        String sessionId = UUID.randomUUID().toString();
        tempCodes.put(sessionId, new TempCode(user.id, code, Instant.now()));
        
        return sessionId;
    }
    
    // Paso 2: Verificar código SMS (algo que TENES)
    public AuthToken completeLogin(String sessionId, String userCode) {
        TempCode tempCode = tempCodes.get(sessionId);
        
        if (tempCode == null) {
            throw new AuthenticationException("Sesión inválida");
        }
        
        // Verificar que no haya expirado (5 minutos)
        if (tempCode.createdAt.plusSeconds(300).isBefore(Instant.now())) {
            tempCodes.remove(sessionId);
            throw new AuthenticationException("Código expirado");
        }
        
        // Verificar código
        if (!tempCode.code.equals(userCode)) {
            throw new AuthenticationException("Código incorrecto");
        }
        
        // Limpiar código usado
        tempCodes.remove(sessionId);
        
        // Generar token de sesión
        return generateAuthToken(tempCode.userId);
    }
}
```

## Métodos de Autenticación

### 1. Basado en Contraseña (Password-Based)

El más común, pero requiere cuidados especiales.

```java
public class PasswordAuthentication {
    
    public boolean authenticate(String username, String password) {
        // Validar entrada
        if (username == null || password == null) {
            return false;
        }
        
        // Buscar usuario
        User user = userRepository.findByUsername(username);
        if (user == null) {
            // Importante: Mismo tiempo de respuesta para usuario inexistente
            // para prevenir enumeración de usuarios
            PasswordHashing.hash("dummy"); // Consumir tiempo
            return false;
        }
        
        // Verificar si cuenta está bloqueada
        if (user.isLocked()) {
            return false;
        }
        
        // Verificar contraseña
        boolean valid = PasswordHashing.verify(password, user.passwordHash);
        
        if (!valid) {
            // Incrementar intentos fallidos
            user.incrementFailedAttempts();
            
            // Bloquear cuenta después de N intentos
            if (user.failedAttempts >= 5) {
                user.lockAccount(Duration.ofMinutes(30));
            }
            
            userRepository.save(user);
            return false;
        }
        
        // Login exitoso: resetear intentos fallidos
        user.resetFailedAttempts();
        user.lastLoginAt = Instant.now();
        userRepository.save(user);
        
        return true;
    }
}
```

### 2. Basado en Token (Token-Based)

Usado en APIs y SPAs.

```java
public class TokenAuthentication {
    
    // Login: Generar token JWT
    public String login(String username, String password) {
        // Verificar credenciales
        User user = authenticateCredentials(username, password);
        if (user == null) {
            throw new AuthenticationException("Credenciales inválidas");
        }
        
        // Generar JWT
        return Jwts.builder()
            .setSubject(user.username)
            .setIssuedAt(new Date())
            .setExpiration(new Date(System.currentTimeMillis() + 3600000)) // 1 hora
            .claim("userId", user.id)
            .claim("role", user.role)
            .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
            .compact();
    }
    
    // Verificar token en cada request
    public User authenticateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
            
            String username = claims.getSubject();
            return userRepository.findByUsername(username);
            
        } catch (ExpiredJwtException e) {
            throw new AuthenticationException("Token expirado");
        } catch (JwtException e) {
            throw new AuthenticationException("Token inválido");
        }
    }
}
```

### 3. API Key Authentication

Común en APIs públicas/privadas.

```java
public class ApiKeyAuthentication {
    
    public Service authenticateApiKey(String apiKey) {
        // Buscar servicio por API key
        Service service = serviceRepository.findByApiKey(apiKey);
        
        if (service == null) {
            throw new AuthenticationException("API key inválida");
        }
        
        // Verificar si está activa
        if (!service.isActive()) {
            throw new AuthenticationException("API key desactivada");
        }
        
        // Verificar rate limiting
        if (rateLimiter.isRateLimited(apiKey)) {
            throw new RateLimitException("Límite de requests excedido");
        }
        
        // Registrar uso
        service.lastUsedAt = Instant.now();
        serviceRepository.save(service);
        
        return service;
    }
    
    // Uso en API REST
    @RestController
    public class ApiController {
        
        @GetMapping("/api/data")
        public Response getData(@RequestHeader("X-API-Key") String apiKey) {
            // Autenticar
            Service service = apiKeyAuth.authenticateApiKey(apiKey);
            
            // Procesar request
            return new Response(data);
        }
    }
}
```

### 4. OAuth 2.0 / OpenID Connect

Autenticación delegada (Login con algun provider Ej.Google).

```java
public class OAuthAuthentication {
    
    // Paso 1: Redirigir a proveedor OAuth
    public String initiateOAuth() {
        String authUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
            "?client_id=" + CLIENT_ID +
            "&redirect_uri=" + REDIRECT_URI +
            "&response_type=code" +
            "&scope=openid%20email%20profile";
        
        return authUrl; // Redirigir usuario aquí
    }
    
    // Paso 2: Callback - intercambiar código por token
    public User handleCallback(String authorizationCode) {
        // Intercambiar código por access token
        TokenResponse tokenResponse = exchangeCodeForToken(authorizationCode);
        
        // Obtener información del usuario
        UserInfo userInfo = getUserInfo(tokenResponse.accessToken);
        
        // Buscar o crear usuario en nuestra BD
        User user = userRepository.findByEmail(userInfo.email);
        if (user == null) {
            user = new User();
            user.email = userInfo.email;
            user.name = userInfo.name;
            user.oauthProvider = "google";
            user.oauthId = userInfo.sub;
            userRepository.save(user);
        }
        
        return user;
    }
}
```

### 5. Biométrica

Huella dactilar, reconocimiento facial, etc.

```java
public class BiometricAuthentication {
    
    public boolean authenticateFingerprint(int userId, byte[] fingerprintData) {
        // Obtener template de huella almacenada
        BiometricTemplate storedTemplate = 
            biometricRepository.findByUserId(userId);
        
        if (storedTemplate == null) {
            return false;
        }
        
        // Comparar usando algoritmo de matching
        double similarity = fingerprintMatcher.compare(
            storedTemplate.data, 
            fingerprintData
        );
        
        // Threshold típico: 0.8-0.9 (80-90% de similitud)
        return similarity >= 0.85;
    }
    
    // Nota: En producción, esto se hace típicamente en el dispositivo
    // y se envía solo un token/certificado al servidor
}
```

### 6. Certificados Digitales (mTLS)

Autenticación mutua con certificados X.509.

```java
public class CertificateAuthentication {
    
    public User authenticateClientCertificate(X509Certificate clientCert) {
        try {
            // Verificar que el certificado sea válido
            clientCert.checkValidity();
            
            // Verificar la cadena de confianza
            if (!isTrustedCertificate(clientCert)) {
                throw new AuthenticationException("Certificado no confiable");
            }
            
            // Extraer información del subject
            String commonName = getCommonName(clientCert.getSubjectDN());
            
            // Buscar usuario asociado al certificado
            User user = userRepository.findByCertificateCommonName(commonName);
            
            if (user == null) {
                throw new AuthenticationException("Usuario no encontrado");
            }
            
            return user;
            
        } catch (CertificateExpiredException e) {
            throw new AuthenticationException("Certificado expirado");
        } catch (CertificateNotYetValidException e) {
            throw new AuthenticationException("Certificado aún no válido");
        }
    }
}
```

## Buenas Prácticas

### ✅ QUE HACER

1. **Usar MFA/2FA siempre que sea posible**
   ```java
   // Especialmente para cuentas privilegiadas
   if (user.isAdmin() || user.hasAccessToSensitiveData()) {
       require2FA(user);
   }
   ```

2. **Implementar rate limiting**
   ```java
   // Limitar intentos de login
   @RateLimit(maxAttempts = 5, windowSeconds = 300)
   public boolean login(String username, String password) {
       // ...
   }
   ```

3. **Usar timing-safe comparisons**
   ```java
   // Evitar timing attacks
   public boolean verifyPassword(String input, String stored) {
       return MessageDigest.isEqual(
           input.getBytes(), 
           stored.getBytes()
       );
   }
   ```

4. **Registrar intentos de autenticación**
   ```java
   // Logging de seguridad
   logger.info("Login attempt: user={}, ip={}, success={}", 
       username, ipAddress, success);
   ```

5. **Bloqueo de cuenta tras intentos fallidos**
   ```java
   if (user.failedAttempts >= MAX_ATTEMPTS) {
       user.lockUntil(Instant.now().plus(30, ChronoUnit.MINUTES));
   }
   ```

6. **Implementar "forgot password" seguro**
   ```java
   // Enviar token de un solo uso con expiración
   String resetToken = generateSecureToken();
   sendEmail(user.email, "Reset link: /reset?token=" + resetToken);
   tokens.put(resetToken, new TokenData(user.id, Instant.now().plusMinutes(15)));
   ```

### ❌ QUE NO HACER

1. **NO almacenar contraseñas en texto plano**
   ```java
   // MAL
   user.password = password;
   
   // BIEN
   user.passwordHash = PasswordHashing.hash(password);
   ```

2. **NO revelar información en mensajes de error**
   ```java
   // MAL: "Usuario no existe" o "Contraseña incorrecta"
   // BIEN: "Credenciales inválidas" (genérico)
   ```

3. **NO permitir contraseñas débiles**
   ```java
   // BIEN: Validar fortaleza
   if (password.length() < 8) {
       throw new ValidationException("Contraseña muy corta");
   }
   ```

4. **NO usar HTTP para autenticación**
   ```java
   // BIEN: Siempre HTTPS
   if (!request.isSecure()) {
       throw new SecurityException("HTTPS requerido");
   }
   ```

## Patrones Comunes

### Patrón: Session-Based Authentication

```java
public class SessionBasedAuth {
    
    // Login: Crear sesión
    public String login(String username, String password) {
        User user = authenticate(username, password);
        
        String sessionId = UUID.randomUUID().toString();
        Session session = new Session(sessionId, user.id, Instant.now());
        sessionRepository.save(session);
        
        return sessionId; // Almacenar en cookie
    }
    
    // Verificar sesión en cada request
    public User getAuthenticatedUser(String sessionId) {
        Session session = sessionRepository.findById(sessionId);
        
        if (session == null || session.isExpired()) {
            return null;
        }
        
        return userRepository.findById(session.userId);
    }
}
```

### Patrón: Stateless Authentication (JWT)

```java
public class StatelessAuth {
    
    // No se almacena sesión en servidor
    // Todo está en el token JWT
    
    public String login(String username, String password) {
        User user = authenticate(username, password);
        
        return createJWT(user); // Cliente guarda este token
    }
    
    public User verify(String jwt) {
        Claims claims = parseJWT(jwt);
        return userRepository.findById(claims.get("userId"));
    }
}
```

## Referencias

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B: Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 6749: OAuth 2.0 Framework](https://tools.ietf.org/html/rfc6749)
- [RFC 7519: JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)