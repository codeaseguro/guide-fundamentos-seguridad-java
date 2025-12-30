package com.codeaseguro.crypto.symmetric;;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * ⚠️⚠️⚠️ ADVERTENCIA: CÓDIGO INSEGURO ⚠️⚠️⚠️
 * 
 * Esta clase contiene DELIBERADAMENTE implementaciones INSEGURAS
 * de cifrado para propósitos EDUCATIVOS.
 * 
 * NUNCA uses estos patrones en producción.
 * Cada método incluye explicaciones de por qué es inseguro.
 * 
 * @author CodeaSeguro
 * @version 1.0
 */
public class BadPractices {
    
    /**
     * ❌ MALA PRÁCTICA #1: Clave hardcodeada
     * 
     * Problemas:
     * - La clave está visible en el código fuente
     * - Cualquiera con acceso al código/binario puede extraerla
     * - Imposible rotar la clave sin recompilar
     * - Si el código se sube a un repositorio público, la clave queda expuesta
     * 
     * Solución correcta:
     * - Usar variables de entorno
     * - Usar sistemas de gestión de secretos (AWS Secrets Manager, HashiCorp Vault)
     * - Usar keystores protegidos
     */
    private static final String HARDCODED_KEY = "MiClaveSuper$ecreta123456"; // NUNCA HACER ESTO
    
    /**
     * ❌ MALA PRÁCTICA #2: IV estático (reutilizado)
     * 
     * Problemas:
     * - Reutilizar el mismo IV con la misma clave es CRÍTICO
     * - En modo CTR/GCM: revela el XOR de dos mensajes
     * - Permite ataques de texto plano conocido
     * - Destruye completamente la seguridad del cifrado
     * 
     * Solución correcta:
     * - Generar un IV aleatorio único para cada operación
     * - Usar SecureRandom para generar el IV
     */
    private static final byte[] STATIC_IV = "1234567890123456".getBytes(); //NUNCA HACER ESTO
    
    /**
     * ❌ MALA PRÁCTICA #3: Usar modo ECB
     * 
     * ECB (Electronic Codebook) es el modo MÁS INSEGURO porque:
     * - Bloques idénticos producen texto cifrado idéntico
     * - Revela patrones en los datos
     * - No proporciona integridad ni autenticación
     * - Vulnerable a ataques de reorganización de bloques
     */
    public static String encryptECB_INSECURE(String plainText) throws Exception {
        // Este código es INSEGURO - solo para demostración
        SecretKeySpec keySpec = new SecretKeySpec(
            HARDCODED_KEY.getBytes(StandardCharsets.UTF_8), 
            0, 
            16, 
            "AES"
        );
        
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ❌ ECB es inseguro
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    /**
     * ❌ MALA PRÁCTICA #4: Reutilizar IV con CBC
     * 
     * Problemas:
     * - Con IV estático, el primer bloque siempre produce el mismo resultado
     * - Permite inferir información sobre el texto plano
     * - Vulnerable a ataques de padding oracle
     */
    public static String encryptCBC_INSECURE(String plainText) throws Exception {
        // ⚠️ Este código es INSEGURO - solo para demostración
        SecretKeySpec keySpec = new SecretKeySpec(
            HARDCODED_KEY.getBytes(StandardCharsets.UTF_8), 
            0, 
            16, 
            "AES"
        );
        
        IvParameterSpec ivSpec = new IvParameterSpec(STATIC_IV); // IV estático
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    /**
     * ❌ MALA PRÁCTICA #5: No validar integridad
     * 
     * Problemas:
     * - Sin MAC o modo autenticado (GCM), los datos pueden ser modificados
     * - Permite ataques de manipulación de datos
     * - No detecta corrupción accidental
     * 
     * Solución correcta:
     * - Usar AES-GCM (incluye autenticación)
     * - O usar HMAC para verificar integridad
     */
    public static String encryptWithoutAuthentication_INSECURE(String plainText) throws Exception {
        // ⚠️ Este código es INSEGURO - solo para demostración
        SecretKeySpec keySpec = new SecretKeySpec(
            HARDCODED_KEY.getBytes(StandardCharsets.UTF_8), 
            0, 
            16, 
            "AES"
        );
        
        // Usar un IV aleatorio es correcto, pero sin autenticación es inseguro
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); // ❌ Sin autenticación
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        
        // Combinar IV + datos cifrados
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
        
        return Base64.getEncoder().encodeToString(combined);
        // No hay forma de verificar si los datos fueron manipulados
    }
    
    /**
     * ❌ MALA PRÁCTICA #6: Usar algoritmos obsoletos
     * 
     * Problemas con DES:
     * - Clave de solo 56 bits (vulnerable a fuerza bruta)
     * - Considerado criptográficamente roto desde los años 90
     * - Prohibido en muchos estándares de seguridad
     */
    public static String encryptDES_INSECURE(String plainText) throws Exception {
        // ⚠️ Este código es INSEGURO - solo para demostración
        SecretKeySpec keySpec = new SecretKeySpec(
            HARDCODED_KEY.getBytes(StandardCharsets.UTF_8), 
            0, 
            8, 
            "DES"
        );
        
        Cipher cipher = Cipher.getInstance("DES"); // DES está obsoleto
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }
    
    /**
     * ❌ MALA PRÁCTICA #7: Clave derivada de forma insegura
     * 
     * Problemas:
     * - Usar contraseñas directamente como claves es débil
     * - No hay "stretching" de clave
     * - Vulnerable a ataques de diccionario
     * 
     * Solución correcta:
     * - Usar PBKDF2, bcrypt o Argon2 para derivar claves
     * - Incluir un salt único
     * - Usar múltiples iteraciones
     */
    public static byte[] deriveKeyInsecure(String password) {
        // NUNCA derivar claves así
        return password.getBytes(StandardCharsets.UTF_8); // Demasiado simple
    }
    
    /**
     * Demostración de las vulnerabilidades
     */
    public static void main(String[] args) {
        System.out.println("=== DEMOSTRACIÓN DE MALAS PRÁCTICAS (NO USAR EN PRODUCCIÓN) ===\n");
        
        try {
            String secretMessage = "Este es un mensaje secreto";
            String repeatedMessage = "AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAA"; // Patrón repetido
            
            // Demostración 1: ECB revela patrones
            System.out.println("1. ECB revela patrones:");
            String ecb1 = encryptECB_INSECURE(repeatedMessage);
            String ecb2 = encryptECB_INSECURE(repeatedMessage);
            System.out.println("Cifrado 1: " + ecb1.substring(0, 40) + "...");
            System.out.println("Cifrado 2: " + ecb2.substring(0, 40) + "...");
            System.out.println("❌ Son idénticos: " + ecb1.equals(ecb2));
            System.out.println("Esto revela que el contenido es el mismo\n");
            
            // Demostración 2: IV estático produce resultados repetidos
            System.out.println("2. IV estático en CBC:");
            String cbc1 = encryptCBC_INSECURE(secretMessage);
            String cbc2 = encryptCBC_INSECURE(secretMessage);
            System.out.println("Cifrado 1: " + cbc1.substring(0, 40) + "...");
            System.out.println("Cifrado 2: " + cbc2.substring(0, 40) + "...");
            System.out.println("❌ Son idénticos: " + cbc1.equals(cbc2));
            System.out.println("El primer bloque siempre es el mismo\n");
            
            // Demostración 3: Sin autenticación
            System.out.println("3. Sin autenticación:");
            String noAuth = encryptWithoutAuthentication_INSECURE(secretMessage);
            System.out.println("Texto cifrado: " + noAuth.substring(0, 40) + "...");
            System.out.println("❌ No hay forma de detectar si fue manipulado\n");
         
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}