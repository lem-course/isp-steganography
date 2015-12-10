package isp.steganography;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import javax.imageio.ImageIO;

/**
 * EXERCISE:
 * <p/>
 * - E1. Ensure initial offset when encoding LSB bits
 * - E2. Ensure Implement changing distance between LSB bits
 * - E3. Implement EOF auto-detection
 * - E4. Switch between RGB values
 * - E5. Use encryption (e.g. AES) to provide bitMessage secrecy
 * - E6. Use HMAC to provide bitMessage authenticity and data integrity
 *
 * @author Iztok Starc <iztok.starc@fri.uni-lj.si>
 * @version 1
 * @date 9. 12. 2013
 */
public class SteganoEncode {

    private final boolean[] bitMessage;

    private final BufferedImage image;

    public SteganoEncode(String sourceFile, String steganogramFile, String message) throws IOException {
        // Load the Image
        image = ImageIO.read(SteganoEncode.class.getResource(sourceFile));

        // Convert String to Bit Sequence
        bitMessage = getBits(message);

        // Encode the Bit Sequence in the PNG
        encode();

        // Save the Image
        ImageIO.write(image, "png", new File(steganogramFile));
    }

    private boolean[] getBits(String x) throws UnsupportedEncodingException {
        final byte[] bytes = x.getBytes("UTF-8");
        final boolean[] bits = new boolean[bytes.length * 8];

        for (int i = 0, bitCounter = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[bitCounter] = (bytes[i] & (0x01 << j)) != 0;
                bitCounter++;
            }
        }

        return bits;
    }

    private void encode() {
        // Traverse all pixels
        for (int i = image.getMinX(), bitCounter = 0; i < image.getWidth() && bitCounter < bitMessage.length; i++) {
            for (int j = image.getMinY(); j < image.getHeight() && bitCounter < bitMessage.length; j++) {

                // Convert the pixel to Alpha, Red, Green, Blue
                final int pixel = image.getRGB(i, j);
                // final int[] argb = pixelToArgb(pixel);
                final Color original = new Color(pixel);

                // Let's use red component only
                final int newRed = bitMessage[bitCounter] ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with new values
                image.setRGB(i, j, modified.getRGB());
                System.out.printf("%03d bit, pixel(%03d, %03d) = %s -> %s%n", bitCounter, i, j, original, modified);

                bitCounter++;
            }
        }
    }

    public static void main(String[] args) throws IOException {
        SteganoEncode se = new SteganoEncode("/1_Kyoto.png", "steganograms/steganogram.png", "Steganography rules!");
    }
}
