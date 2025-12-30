package com.codeaseguro.crypto.symmetric;

import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Implementación segura de cifrado RSA con OAEP padding.
 * 
 * RSA (Rivest-Shamir-Adleman) es un algoritmo de cifrado asimétrico que usa
 * un par de claves: pública (para cifrar) y privada (para descifrar).
 * 
 * IMPORTANTE: 
 * - RSA es lento y tiene límites de tamaño
 * - Para datos grandes, usar cifrado híbrido (RSA + AES)
 * - Siempre usar OAEP padding, nunca PKCS1 o NoPadding
 * 
 * @author CodeaSeguro
 * @version 1.0
 */
public class RSAEncryption {
    
    // Configuración segura
    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int DEFAULT_KEY_SIZE = 2048; // bits
    
    /**
     * Genera un par de claves RSA (pública y privada).
     * 
     * @param keySize Tamaño de la clave en bits (2048, 3072, o 4096 recomendado)
     * @return Par de claves generado
     * @throws NoSuchAlgorithmException si RSA no está disponible
     */
    public static KeyPair generateKeyPair(int keySize) throws NoSuchAlgorithmException {
        // Validar tamaño de clave
        if (keySize < 2048) {
            throw new IllegalArgumentException(
                "Tamaño de clave inseguro. Mínimo: 2048 bits, recomendado: 3072+"
            );
        }
        
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
        keyGen.initialize(keySize, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    
    /**
     * Genera un par de claves RSA con tamaño por defecto (2048 bits).
     * 
     * @return Par de claves generado
     * @throws NoSuchAlgorithmException si RSA no está disponible
     */
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        return generateKeyPair(DEFAULT_KEY_SIZE);
    }
    
    /**
     * Cifra un texto usando la clave pública.
     * 
     * IMPORTANTE: RSA tiene un límite de tamaño basado en el tamaño de la clave:
     * - RSA 2048 con OAEP: máximo ~190 bytes
     * - RSA 3072 con OAEP: máximo ~318 bytes
     * - RSA 4096 con OAEP: máximo ~446 bytes
     * 
     * Para textos más largos, usar cifrado híbrido (ver HybridEncryption.java)
     * 
     * @param plainText Texto a cifrar
     * @param publicKey Clave pública
     * @return Texto cifrado en Base64
     * @throws Exception si hay error en el cifrado
     */
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        // Configurar OAEP con SHA-256
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
            "SHA-256",                    // Algoritmo de hash
            "MGF1",                       // Mask Generation Function
            MGF1ParameterSpec.SHA256,     // MGF1 con SHA-256
            PSource.PSpecified.DEFAULT    // Sin etiqueta
        );
        
        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
        
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
    
    /**
     * Descifra un texto usando la clave privada.
     * 
     * @param encryptedText Texto cifrado en Base64
     * @param privateKey Clave privada
     * @return Texto descifrado
     * @throws Exception si hay error en el descifrado o la clave es incorrecta
     */
    public static String decrypt(String encryptedText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        
        // Misma configuración OAEP que en cifrado
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            PSource.PSpecified.DEFAULT
        );
        
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        
        return new String(decryptedBytes, "UTF-8");
    }
    
    /**
     * Convierte una clave pública a formato Base64 (para almacenamiento/transmisión).
     * 
     * @param publicKey Clave pública
     * @return String en Base64
     */
    public static String publicKeyToString(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
    
    /**
     * Convierte una clave privada a formato Base64.
     * 
     * ⚠️ ADVERTENCIA: La clave privada debe mantenerse SECRETA.
     * Considera cifrarla antes de almacenarla.
     * 
     * @param privateKey Clave privada
     * @return String en Base64
     */
    public static String privateKeyToString(PrivateKey privateKey) {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }
    
    /**
     * Reconstruye una clave pública desde su representación en Base64.
     * 
     * @param keyString String en Base64
     * @return Clave pública reconstruida
     * @throws Exception si hay error al reconstruir la clave
     */
    public static PublicKey stringToPublicKey(String keyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(spec);
    }
    
    /**
     * Reconstruye una clave privada desde su representación en Base64.
     * 
     * @param keyString String en Base64
     * @return Clave privada reconstruida
     * @throws Exception si hay error al reconstruir la clave
     */
    public static PrivateKey stringToPrivateKey(String keyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }
    
    /**
     * Calcula el tamaño máximo de datos que se pueden cifrar.
     * 
     * @param keySize Tamaño de clave en bits
     * @return Tamaño máximo en bytes
     */
    public static int getMaxPlaintextSize(int keySize) {
        // Con OAEP (SHA-256): overhead = 2 * hashLen + 2 = 2 * 32 + 2 = 66 bytes
        int keySizeBytes = keySize / 8;
        int oaepOverhead = 66;
        return keySizeBytes - oaepOverhead;
    }
    
    /**
     * Obtiene información sobre un par de claves.
     * 
     * @param keyPair Par de claves
     * @return String con información
     */
    public static String getKeyInfo(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // Obtener tamaño de la clave
        int keySize = 0;
        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsaPublicKey = 
                (java.security.interfaces.RSAPublicKey) publicKey;
            keySize = rsaPublicKey.getModulus().bitLength();
        }
        
        StringBuilder info = new StringBuilder();
        info.append("=== Información de Claves RSA ===\n");
        info.append("Algoritmo: ").append(publicKey.getAlgorithm()).append("\n");
        info.append("Tamaño de clave: ").append(keySize).append(" bits\n");
        info.append("Formato clave pública: ").append(publicKey.getFormat()).append("\n");
        info.append("Formato clave privada: ").append(privateKey.getFormat()).append("\n");
        info.append("Tamaño máximo de texto plano: ").append(getMaxPlaintextSize(keySize)).append(" bytes\n");
        
        return info.toString();
    }
    
    /**
     * Ejemplo de uso completo de RSA.
     */
    public static void main(String[] args) {
        try {
            System.out.println("=== Demostración de Cifrado RSA ===\n");
            
            // 1. Generar par de claves
            System.out.println("1. Generando par de claves RSA (2048 bits)...");
            long startTime = System.currentTimeMillis();
            KeyPair keyPair = generateKeyPair(2048);
            long genTime = System.currentTimeMillis() - startTime;
            System.out.println("Claves generadas en " + genTime + "ms\n");
            
            // Mostrar información de las claves
            System.out.println(getKeyInfo(keyPair));
            
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            // 2. Mensaje a cifrar
            String originalMessage = "Este es un mensaje secreto que debe ser protegido con RSA";
            System.out.println("2. Mensaje original:");
            System.out.println("\"" + originalMessage + "\"");
            System.out.println("Longitud: " + originalMessage.length() + " caracteres\n");
            
            // 3. Cifrar con clave pública
            System.out.println("3. Cifrando con clave pública...");
            startTime = System.currentTimeMillis();
            String encryptedMessage = encrypt(originalMessage, publicKey);
            long encTime = System.currentTimeMillis() - startTime;
            System.out.println("Mensaje cifrado en " + encTime + "ms");
            System.out.println("Texto cifrado (Base64): " + encryptedMessage.substring(0, 60) + "...");
            System.out.println("Longitud: " + encryptedMessage.length() + " caracteres\n");
            
            // 4. Descifrar con clave privada
            System.out.println("4. Descifrando con clave privada...");
            startTime = System.currentTimeMillis();
            String decryptedMessage = decrypt(encryptedMessage, privateKey);
            long decTime = System.currentTimeMillis() - startTime;
            System.out.println("Mensaje descifrado en " + decTime + "ms");
            System.out.println("Texto descifrado: \"" + decryptedMessage + "\"\n");
            
            // 5. Verificar que coinciden
            boolean matches = originalMessage.equals(decryptedMessage);
            System.out.println("5. Verificación:");
            System.out.println("¿Mensaje original == Mensaje descifrado? " + (matches ? "✓ SÍ" : "✗ NO"));
            
            // 6. Demostrar serialización de claves
            System.out.println("\n6. Serialización de claves:");
            String publicKeyStr = publicKeyToString(publicKey);
            String privateKeyStr = privateKeyToString(privateKey);
            System.out.println("Clave pública (Base64): " + publicKeyStr.substring(0, 50) + "...");
            System.out.println("Clave privada (Base64): " + privateKeyStr.substring(0, 50) + "...");
            
            // 7. Reconstruir claves desde strings
            System.out.println("\n7. Reconstruyendo claves desde Base64...");
            PublicKey reconstructedPublic = stringToPublicKey(publicKeyStr);
            PrivateKey reconstructedPrivate = stringToPrivateKey(privateKeyStr);
            System.out.println("Claves reconstruidas exitosamente");
            
            // 8. Probar con claves reconstruidas
            System.out.println("\n8. Probando con claves reconstruidas...");
            String testMessage = "Prueba con claves reconstruidas";
            String encryptedTest = encrypt(testMessage, reconstructedPublic);
            String decryptedTest = decrypt(encryptedTest, reconstructedPrivate);
            System.out.println("Original: \"" + testMessage + "\"");
            System.out.println("Descifrado: \"" + decryptedTest + "\"");
            System.out.println("Ok" + (testMessage.equals(decryptedTest) ? "Funcionan correctamente" : "Error"));
            
            // 9. Demostrar límite de tamaño
            System.out.println("\n9. Límite de tamaño:");
            int maxSize = getMaxPlaintextSize(2048);
            System.out.println("Tamaño máximo con RSA 2048: " + maxSize + " bytes");
            System.out.println("Para mensajes más largos, usar cifrado híbrido (RSA + AES)");
            

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}