package isp.steganography;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import javax.imageio.ImageIO;

/**
 * EXERCISE:
 * <p/>
 * - E1. Ensure initial offset when encoding LSB bits
 * - E2. Ensure Implement changing distance between LSB bits
 * - E3. Implement EOF auto-detection
 * - E4. Switch between RGB values
 * - E5. Use encryption (e.g. AES) to provide bits secrecy
 * - E6. Use HMAC to provide bits authenticity and data integrity
 */
public class Steganography {

    protected String inFile;
    protected String outFile;

    public Steganography(final String inFile, final String outFile) {
        this.inFile = inFile;
        this.outFile = outFile;
    }

    protected boolean[] getBits(final byte[] bytes) {
        final boolean[] bits = new boolean[bytes.length * 8];

        for (int i = 0, bitCounter = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[bitCounter] = (bytes[i] & (0x01 << j)) != 0;
                bitCounter++;
            }
        }

        return bits;
    }

    protected BufferedImage loadFile(final String inFile) throws IOException {
        return ImageIO.read(Steganography.class.getResource(inFile));
    }

    protected BufferedImage encode(final String file, final boolean[] message) throws IOException {
        final BufferedImage image = loadFile(file);

        for (int i = image.getMinX(), bitCounter = 0; i < image.getWidth() && bitCounter < message.length; i++) {
            for (int j = image.getMinY(); j < image.getHeight() && bitCounter < message.length; j++) {
                final Color original = new Color(image.getRGB(i, j));

                // Let's modify the red component only
                final int newRed = message[bitCounter] ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                // Create a new color
                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with new one
                image.setRGB(i, j, modified.getRGB());

                System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);

                bitCounter++;
            }
        }

        return image;
    }

    public void encode(final byte[] payload) throws IOException {
        // Convert byte array to bit sequence (actually, to an array of booleans)
        final boolean[] bits = getBits(payload);

        // encode the bits into image
        final BufferedImage image = encode(inFile, bits);

        // save
        ImageIO.write(image, "png", new File(outFile));
    }

    public static void main(String[] args) throws IOException {
        final Steganography se = new Steganography("/1_Kyoto.png", "steganograms/steganogram.png");
        se.encode("Steganography rules!".getBytes("UTF-8"));
    }
}
