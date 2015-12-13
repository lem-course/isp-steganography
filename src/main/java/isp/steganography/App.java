package isp.steganography;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class App {
    public static void main(String[] args)
            throws IOException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException,
            BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
        final String secretMessage = "Steganography rules!";
        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final ImageSteganography encode = new ImageSteganography("images/1_Kyoto.png", key);
        encode.encodeAndEncrypt("images/steganogram.png", secretMessage.getBytes("UTF-8"));

        final ImageSteganography decode = new ImageSteganography("images/steganogram.png", key);
        final byte[] decoded = decode.decode();

        System.out.printf("Decoded: %s%n", new String(decoded, "UTF-8"));
    }
}
