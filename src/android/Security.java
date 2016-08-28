package cn.sunline.cipher;

//Cordova imports

import android.content.Context;
import android.util.Base64;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//Android imports
//import android.provider.Settings;
//Package Cryptografy
//import sun.misc.*;
//JSON Imports


public class Security extends CordovaPlugin {
    //Define some constants for the supported actions
    public static final String AES_ENCRYPT = "aesEncrypt";
    public static final String AES_DECRYPT = "aesDecrypt";
    public static final String ENCRYPT = "encrypt";
    public static final String DECRYPT = "decrypt";
    public static String IV = "0102030405060708";


    public void initialize(CordovaInterface cordova, CordovaWebView webView) {
        super.initialize(cordova, webView);

        //The plugin doesn't have direct access to the
        //application context, so you have to get it first
        Context context = this.cordova.getActivity().getApplicationContext();
    }

    @Override
    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
        final String text = args.getString(0);
        final String key = args.getString(1);

        //First check on the getCarrierName
        if (AES_ENCRYPT.equals(action)) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String cipherTeks = encrypt(text, key);
                        callbackContext.success(cipherTeks);
                    } catch (Exception e) {
                        String error = "加密失败: " + e.getMessage();
                        System.err.println(error);
                        callbackContext.error(error);
                    }
                }
            });
            return true;
        } else if (AES_DECRYPT.equals(action)) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String decryptedTeks = decrypt(text, key);
                        callbackContext.success(decryptedTeks);
                    } catch (Exception e) {
                        String error = "解密失败: " + e.getMessage();
                        System.err.println(error);
                        callbackContext.error(error);
                    }
                }
            });
            return true;
        } else if (ENCRYPT.equals(action)) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String cipherTeks = encryptWithEncodeKey(text, key);
                        callbackContext.success(cipherTeks);
                    } catch (Exception e) {
                        String error = "加密失败: " + e.getMessage();
                        System.err.println(error);
                        callbackContext.error(error);
                    }
                }
            });
            return true;
        } else if (DECRYPT.equals(action)) {
            cordova.getThreadPool().execute(new Runnable() {
                public void run() {
                    try {
                        String decryptedTeks = decryptWithEncodeKey(text, key);
                        callbackContext.success(decryptedTeks);
                    } catch (Exception e) {
                        String error = "解密失败: " + e.getMessage();
                        System.err.println(error);
                        callbackContext.error(error);
                    }
                }
            });
            return true;
        }

        //We don't have a match, so it must be an invalid action
        callbackContext.error("Invalid Action");
        return false;

    }

    public static String encrypt(String plainText, String encryptionKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        String s = Base64.encodeToString(cipher.doFinal(plainText.getBytes("UTF-8")), Base64.DEFAULT);
        return s;
    }

    public static String decrypt(String cipherText, String encryptionKey) throws Exception {
        byte[] decodeCipher = Base64.decode(cipherText, Base64.DEFAULT);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        return new String(cipher.doFinal(decodeCipher), "UTF-8");
    }

    public static String encryptWithEncodeKey(String plainText, String encodeKey) throws Exception {
        byte[] encryptionKey = Base64.decode(encodeKey, Base64.DEFAULT);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(encryptionKey, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        String s = Base64.encodeToString(cipher.doFinal(plainText.getBytes("UTF-8")), Base64.DEFAULT);
        return s;
    }

    public static String decryptWithEncodeKey(String cipherText, String encodeKey) throws Exception {
        byte[] encryptionKey = Base64.decode(encodeKey, Base64.DEFAULT);
        byte[] decodeCipher = Base64.decode(cipherText, Base64.DEFAULT);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec key = new SecretKeySpec(encryptionKey, "AES");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV.getBytes("UTF-8")));
        return new String(cipher.doFinal(decodeCipher), "UTF-8");
    }
}