package server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CriptografiaAES {

    public static byte[] criptografar(String texto, SecretKey chaveAES) {
        byte[] cipherText = null;

        try {
            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.ENCRYPT_MODE, chaveAES);

            cipherText = cipher.doFinal(texto.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }

        return cipherText;
    }

    public static String descriptografar(byte[] texto, SecretKey chaveAES) {
        byte[] dectyptedText = null;

        try {
            Cipher cipher = Cipher.getInstance("AES");

            cipher.init(Cipher.DECRYPT_MODE, chaveAES);

            dectyptedText = cipher.doFinal(texto);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return new String(dectyptedText);
    }

}
