package com.nrup.encryptionDecryption;

import android.util.Base64;

import java.nio.charset.StandardCharsets;

public class AppUtils {


    public static byte[] decode(String data, int padding) {
        return Base64.decode(data.getBytes(StandardCharsets.UTF_8), padding);
    }

    public static String toBase64(byte[] data, int padding) {
        return Base64.encodeToString(data, padding);
    }
}
