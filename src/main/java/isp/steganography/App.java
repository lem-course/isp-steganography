package isp.steganography;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class App {
    public static void main(String[] args) throws Exception {
        final byte[] payload = "My secret message".getBytes("UTF-8");

        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded1 = ImageSteganography.decode("images/steganogram.png");
        System.out.printf("Decoded: %s%n", new String(decoded1, "UTF-8"));

        final SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        ImageSteganography.encryptAndEncode(payload, "images/2_Morondava.png", "images/steganogram-encrypted.png", key);
        final byte[] decoded2 = ImageSteganography.decryptAndDecode("images/steganogram-encrypted.png", key);

        System.out.printf("Decoded: %s%n", new String(decoded2, "UTF-8"));
    }
}
