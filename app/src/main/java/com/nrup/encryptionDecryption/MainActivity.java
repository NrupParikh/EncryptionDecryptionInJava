package com.nrup.encryptionDecryption;

import android.os.Bundle;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import android.util.Pair;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private Button btnEncryption, btnDecryption;
    private EditText edtPlainText;
    private TextView tvEncryptedText, tvDecryptedText;
    private KeyStoreServiceHelper helper;

    private String actualMasterKey = "5OzXukCXg4eYSoJ2+Q/5g+k4AH92qFWBxxOXU7Fazn8=";
    private String encryptedSymmetricKey = "";
    private String encryptedPassword = "";

    private void initializeData() {

        btnEncryption = (Button) findViewById(R.id.btnEncryption);
        btnDecryption = (Button) findViewById(R.id.btnDecryption);
        edtPlainText = (EditText) findViewById(R.id.edtPlainText);
        tvEncryptedText = (TextView) findViewById(R.id.tvEncryptedText);
        tvDecryptedText = (TextView) findViewById(R.id.tvDecryptedText);

        btnEncryption.setOnClickListener(this);
        btnDecryption.setOnClickListener(this);

        helper = KeyStoreServiceHelper.getInstance();
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.layout_main_activity);
        initializeData();
    }

    private Pair getEncryptedSymmetricKeyAndPassword(KeyStoreServiceHelper helper, String plainPassword) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // ===================================================
        // Part 1 (Encrypt symmetric key using Master key)
        // ===================================================

        String plaintext = helper.generateSymmetricKey();
        Log.e("TAG_SYMMETRIC_kEY", "" + plaintext);
        byte[] decodedKey = AppUtils.decode(actualMasterKey, Base64.NO_WRAP);
        String encryptedSymmetricKey = helper.doEncryption(
                plaintext,
                new SecretKeySpec(decodedKey, "AES")
        );

        Log.e("TAG_SYM_KEY", encryptedSymmetricKey);

        // ===================================================
        // Part 2 (Encrypt password text using symmetric key)
        // ===================================================

        byte[] decodeSecretKey = AppUtils.decode(plaintext, Base64.NO_WRAP);
        Log.e("TAG_ENCRYPTED_SYMMETRIC_KEY", "" + encryptedSymmetricKey);
        String encryptedPassword = helper.doEncryption(plainPassword, new SecretKeySpec(decodeSecretKey, "AES"));
        Log.e("TAG_ENCRYPTED_PASSWORD", encryptedPassword);

        return new Pair<>(encryptedPassword, encryptedSymmetricKey);

    }


    private String getPasswordFromEncryptedSymmetricKey(String encryptedSymmetricKey, String encryptedPassword) throws NoSuchAlgorithmException {

        // ===================================================
        // Part 1 (Decrypt symmetric key using Master key)
        // ===================================================

        byte[] decodedKey = AppUtils.decode(actualMasterKey, Base64.NO_WRAP);

        String data = encryptedSymmetricKey.split("::")[0];
        String IV = encryptedSymmetricKey.split("::")[1];

        Log.d("TAG_DECRYPTION", "=============");
        Log.d("TAG_SYM_DATA", data);
        Log.d("TAG_SYM_IV", IV);


        byte[] secureKeyData = AppUtils.decode(data, Base64.NO_WRAP);
        byte[] secureKeyIVData = AppUtils.decode(IV, Base64.NO_WRAP);

        try {

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "AES");
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, secureKeyIVData);

            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

            byte[] decryptedData = cipher.doFinal(secureKeyData);
            String plainSymmetricKey = new String(decryptedData, StandardCharsets.UTF_8);
            Log.d("TAG_Final_Symmetric_Key", plainSymmetricKey);

            byte[] keyData = AppUtils.decode(plainSymmetricKey, Base64.NO_WRAP);

            // Now, symmetricKey is your decrypted key. Used to Decrypt the Password
            SecretKeySpec symmetricKey = new SecretKeySpec(keyData, "AES");


            // ===================================================
            // Part 2 (Decrypt password using symmetric key)
            // ===================================================

            String data2 = encryptedPassword.split("::")[0];
            String IV2 = encryptedPassword.split("::")[1];

            Log.d("TAG_DECRYPTION", "=============");
            Log.d("TAG_PASS_DATA", data2);
            Log.d("TAG_PASS_IV", IV2);

            byte[] securePasswordData = AppUtils.decode(data2, Base64.NO_WRAP);
            byte[] securePasswordIVData = AppUtils.decode(IV2, Base64.NO_WRAP);

            Cipher cipher2 = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmParameterSpec2 = new GCMParameterSpec(128, securePasswordIVData);
            cipher2.init(Cipher.DECRYPT_MODE, symmetricKey, gcmParameterSpec2);
            byte[] decryptedData2 = cipher2.doFinal(securePasswordData);
            String password = new String(decryptedData2, StandardCharsets.UTF_8);
            Log.d("TAG_Final_Plain_Pass", password);

            return password;
        } catch (Exception e) {
            e.printStackTrace();
            // Handle the exception
        }
        return "";
    }


    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.btnEncryption) {
            String plainText = edtPlainText.getText().toString().trim();
            if (!TextUtils.isEmpty(plainText)) {
                String plainPassword = edtPlainText.getText().toString().trim();

                Pair<String, String> data = null;

                try {
                    data = getEncryptedSymmetricKeyAndPassword(helper, plainPassword);
                } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                         NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException |
                         InvalidKeyException e) {
                    throw new RuntimeException(e);
                }

                encryptedPassword = data.first;
                encryptedSymmetricKey = data.second;

                Log.d("TAG_E_Pass", encryptedPassword);
                Log.d("TAG_E_S_Key", encryptedSymmetricKey);

                tvEncryptedText.setText(encryptedPassword);

            } else {
                Toast.makeText(this, "Please enter text", Toast.LENGTH_SHORT).show();
            }


        } else if (v.getId() == R.id.btnDecryption) {
            try {
                String plainPassword = getPasswordFromEncryptedSymmetricKey(encryptedSymmetricKey, encryptedPassword);
                tvDecryptedText.setText(plainPassword);

            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            }
        }
    }
}

