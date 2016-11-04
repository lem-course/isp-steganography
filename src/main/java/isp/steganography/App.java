package isp.steganography;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class App {
    public static void main(String[] args) throws Exception {
        final byte[] payload = "My secret message".getBytes("UTF-8");

        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();

        ImageSteganography.encryptAndEncode(payload, "images/1_Kyoto.png", "images/steganogram.png", key);
        final byte[] decoded = ImageSteganography.decryptAndDecode("images/steganogram.png", key);

        //ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        //final byte[] decoded = ImageSteganography.decode("images/steganogram.png");

        System.out.printf("Decoded: %s%n", new String(decoded, "UTF-8"));
    }
}
