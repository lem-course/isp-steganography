package isp.steganography;

import java.io.IOException;

public class App {
    public static void main(String[] args) throws IOException {
        final String secretMessage = "Steganography rules!";
        final int messageLength = secretMessage.length();

        final ImageSteganography encode = new ImageSteganography("images/1_Kyoto.png", "images/steganogram.png");
        encode.encode(secretMessage.getBytes("UTF-8"));

        final ImageSteganography decode = new ImageSteganography("images/steganogram.png");
        final byte[] decoded = decode.decode(messageLength);

        System.out.printf("Decoded: %s%n", new String(decoded, "UTF-8"));
    }
}
