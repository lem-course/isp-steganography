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
public class ImageSteganography {

    protected String inFile;
    protected String outFile;

    public ImageSteganography(final String inFile, final String outFile) {
        this.inFile = inFile;
        this.outFile = outFile;
    }

    /**
     * Converts an array of bytes it into an array of bits (booleans)
     *
     * @param bytes
     * @return
     */
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

    /**
     * Loads a file from given name and returns an instance of the BufferedImage
     * <p/>
     * The file has to be located in src/main/resources directory.
     *
     * @param inFile
     * @return
     * @throws IOException If file does not exist
     */
    protected BufferedImage loadFile(final String inFile) throws IOException {
        return ImageIO.read(ImageSteganography.class.getResource(inFile));
    }

    /**
     * Encodes given array of bits into given image. The algorithm modifies the
     * least significant bit in the red component of each image pixel.
     *
     * @param payload The array of bits
     * @param image   The image onto which the payload is to be encoded
     */
    private final void encode(final boolean[] payload, final BufferedImage image) {
        for (int i = image.getMinX(), bitCounter = 0; i < image.getWidth() && bitCounter < payload.length; i++) {
            for (int j = image.getMinY(); j < image.getHeight() && bitCounter < payload.length; j++) {
                final Color original = new Color(image.getRGB(i, j));

                // Let's modify the red component only
                final int newRed = payload[bitCounter] ?
                        original.getRed() | 0x01 : // sets LSB to 1
                        original.getRed() & 0xfe;  // sets LSB to 0

                // Create a new color object
                final Color modified = new Color(newRed, original.getGreen(), original.getBlue());

                // Replace the current pixel with the new color
                image.setRGB(i, j, modified.getRGB());

                System.out.printf("%03d bit [%d, %d]: %s -> %s%n", bitCounter, i, j, original, modified);

                bitCounter++;
            }
        }
    }

    public void encode(final byte[] payload) throws IOException {
        // Convert byte array to bit sequence (actually, to an array of booleans)
        final boolean[] bits = getBits(payload);

        // encode the bits into image
        final BufferedImage image = loadFile(inFile);

        // encode the bits into image
        encode(bits, image);

        // save the modified image into outFile
        ImageIO.write(image, "png", new File(outFile));
    }

    public static void main(String[] args) throws IOException {
        final ImageSteganography se = new ImageSteganography("/1_Kyoto.png", "steganograms/steganogram.png");
        se.encode("Steganography rules!".getBytes("UTF-8"));
    }
}
