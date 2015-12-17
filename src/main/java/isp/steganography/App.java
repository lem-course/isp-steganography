package isp.steganography;

import javax.crypto.KeyGenerator;
import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

public class App {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        final String secretMessage = "Steganography rules!";

        final ImageSteganography encoder = new ImageSteganography("images/1_Kyoto.png");
        encoder.doEncode("images/steganogram.png", secretMessage.getBytes("UTF-8"));

        final ImageSteganography decoder = new ImageSteganography("images/steganogram.png");
        final byte[] decoded = decoder.decode();
        System.out.println(new String(decoded, "UTF-8"));

        final Key key = KeyGenerator.getInstance("AES").generateKey();

        final ImageSteganography encodeAndEncrypt = new ImageSteganography("images/1_Kyoto.png", key);
        encodeAndEncrypt.encode("images/steganogram2.png", secretMessage.getBytes("UTF-8"));

        final ImageSteganography decodeAndDecrypt = new ImageSteganography("images/steganogram2.png", key);
        final byte[] decodedAndDecrypted = decodeAndDecrypt.decode();
        System.out.printf("Decoded and decrypted: %s%n", new String(decodedAndDecrypted, "UTF-8"));
    }
}
