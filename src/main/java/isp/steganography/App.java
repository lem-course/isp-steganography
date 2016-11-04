package isp.steganography;

import java.io.IOException;

public class App {
    public static void main(String[] args) throws IOException {
        final byte[] payload = "Steganography rules!".getBytes("UTF-8");
        final int messageLength = payload.length;

        ImageSteganography.encode(payload, "images/1_Kyoto.png", "images/steganogram.png");
        final byte[] decoded = ImageSteganography.decode("images/steganogram.png", messageLength);

        System.out.printf("Decoded: %s%n", new String(decoded, "UTF-8"));
    }
}
