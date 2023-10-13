package com.nrup.encryptionDecryption;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class KeyStoreServiceHelper {

    private static final int GCM_IV_SIZE_BYTES = 12;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_SIZE_BITS = 128;
    private static KeyStoreServiceHelper keyStoreServiceHelper;

    public static KeyStoreServiceHelper getInstance() {
        if (keyStoreServiceHelper == null) {
            keyStoreServiceHelper = new KeyStoreServiceHelper();
        }
        return keyStoreServiceHelper;
    }


    public String generateSymmetricKey() throws NoSuchAlgorithmException {
        //Generate AES symmetric key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        return Base64.encodeToString(secretKey.getEncoded(), Base64.NO_WRAP);
    }

    public String doEncryption(String plaintext, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[GCM_IV_SIZE_BYTES];
        random.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_SIZE_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        final byte[] latestIV = cipher.getIV();
        final byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return AppUtils.toBase64(ciphertext, Base64.NO_WRAP)
                + "::" + AppUtils.toBase64(latestIV, Base64.NO_WRAP);
    }
}
