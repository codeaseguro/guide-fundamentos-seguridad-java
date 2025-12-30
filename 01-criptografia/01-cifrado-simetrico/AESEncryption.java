package com.codeaseguro.crypto.symmetric;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implementación segura de cifrado AES-256-GCM.
 * 
 * AES-GCM (Galois/Counter Mode) proporciona:
 * - Confidencialidad (cifrado)
 * - Autenticidad (detecta modificaciones)
 * - Integridad (detecta corrupción)
 * 
 * @author CodeaSeguro
 * @version 1.0
 */
public class AESEncryption {
    
    // Constantes de configuración segura
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256; // bits
    private static final int IV_SIZE = 12; // bytes (96 bits recomendado para GCM)
    private static final int TAG_SIZE = 128; // bits (tamaño del tag de autenticación)
    
    /**
     * Genera una clave AES segura de 256 bits.
     * 
     * @return SecretKey generada
     * @throws Exception si hay error en la generación
     */
    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE, new SecureRandom());
        return keyGen.generateKey();
    }
    
    /**
     * Convierte una clave a su representación en Base64.
     * 
     * @param key La clave a convertir
     * @return String en Base64
     */
    public static String keyToString(SecretKey key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * Reconstruye una SecretKey desde su representación en Base64.
     * 
     * @param keyString String en Base64
     * @return SecretKey reconstruida
     */
    public static SecretKey stringToKey(String keyString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
    }
    
    /**
     * Cifra un texto plano usando AES-GCM.
     * 
     * Formato del resultado: [IV (12 bytes)][Texto Cifrado + Tag]
     * Todo codificado en Base64 para facilitar almacenamiento.
     * 
     * @param plainText Texto a cifrar
     * @param key Clave de cifrado
     * @return Texto cifrado en Base64
     * @throws Exception si hay error en el cifrado
     */
    public static String encrypt(String plainText, SecretKey key) throws Exception {
        // Generamos un IV único y aleatorio
        byte[] iv = new byte[IV_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        
        // Configuramos el cifrador
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        // Ciframos el texto
        byte[] encryptedData = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        
        // Ralizamos la combinacion de IV + datos cifrados
        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + encryptedData.length);
        byteBuffer.put(iv);
        byteBuffer.put(encryptedData);
        
        // Codificamos en Base64 para almacenarlo facilmente
        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }
    
    /**
     * Descifra un texto cifrado con AES-GCM.
     * 
     * @param encryptedText Texto cifrado en Base64
     * @param key Clave de descifrado (debe ser la misma usada para cifrar)
     * @return Texto plano descifrado
     * @throws Exception si hay error en el descifrado o los datos fueron manipulados
     */
    public static String decrypt(String encryptedText, SecretKey key) throws Exception {
        // Decodificamos desde Base64
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedText);
        
        // Separaramos IV y datos cifrados
        ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedBytes);
        byte[] iv = new byte[IV_SIZE];
        byteBuffer.get(iv);
        byte[] cipherText = new byte[byteBuffer.remaining()];
        byteBuffer.get(cipherText);
        
        // Configuramos el descifrador
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(TAG_SIZE, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
        
        // Desciframos (esto también verifica la autenticidad)
        byte[] decryptedData = cipher.doFinal(cipherText);
        
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
    
    /**
     * Ejemplo de uso.
     */
    public static void main(String[] args) {
        try {
            System.out.println("=== Ejemplo de Cifrado AES-256-GCM ===\n");
            
            // 1. Generar clave
            SecretKey key = generateKey();
            System.out.println("Clave generada: " + keyToString(key).substring(0, 20) + "...");
            
            // 2. Texto a cifrar
            String originalText = "Este es un mensaje secreto que debe ser protegido";
            System.out.println("Texto original: " + originalText);
            
            // 3. Cifrar
            String encrypted = encrypt(originalText, key);
            System.out.println("Texto cifrado: " + encrypted.substring(0, 40) + "...");
            System.out.println("Longitud: " + encrypted.length() + " caracteres");
            
            // 4. Descifrar
            String decrypted = decrypt(encrypted, key);
            System.out.println("Texto descifrado: " + decrypted);
            
            // 5. Verificar
            System.out.println("\nEstado del decifrado: " + originalText.equals(decrypted));
            
            // 6. Demostrar que cada cifrado es diferente (gracias al IV único)
            System.out.println("\n=== Demostración de IV único ===");
            String encrypted1 = encrypt(originalText, key);
            String encrypted2 = encrypt(originalText, key);
            System.out.println("Mismo texto, cifrado 1: " + encrypted1.substring(0, 40) + "...");
            System.out.println("Mismo texto, cifrado 2: " + encrypted2.substring(0, 40) + "...");
            System.out.println("¿Son diferentes? " + !encrypted1.equals(encrypted2));
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}