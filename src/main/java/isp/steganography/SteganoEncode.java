package isp.steganography;

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

    public SteganoEncode(String srcFile, String dstFile, String message) throws IOException {
        // Load the Image
        image = ImageIO.read(SteganoEncode.class.getResource(srcFile));

        // Convert String to Bit Sequence
        bitMessage = getBits(message);

        // Encode the Bit Sequence in the PNG
        encode();

        // Save the Image
        ImageIO.write(image, "png", new File(dstFile));
    }

    private boolean[] getBits(String x) throws UnsupportedEncodingException {
        final byte[] bytes = x.getBytes("UTF-8");
        final boolean[] bits = new boolean[bytes.length * 8];

        for (int i = 0, bitCounter = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                // Isolate individual bit and store to bits
                bits[bitCounter] = ((bytes[i] & (0x01 << j)) == 1);
                bitCounter++;
            }
        }
        return bits;
    }

    private void encode() {
        // Iterate from min.x to max.x
        for (int i = image.getMinX(), cnt = 0; i != image.getWidth(); i++) {
            // Iterate from min.y to max.y
            for (int j = image.getMinY(); j != image.getHeight(); j++) {

                // Get the current pixel and convert to Alpha, Red, Green, Blue
                int pixel = image.getRGB(i, j);
                int[] argb = pixelToRgba(pixel);
                System.out.println(cnt + " Before -- Pixel (" + i + "," + j + "): Alpha: " + argb[0] + ", Red: " + argb[1] + ", Green: " + argb[2] + ", Blue: " + argb[3]);

                // Encode current bit in the LSB of the red pixel 
                if (bitMessage[cnt] == true)
                    argb[1] = argb[1] & 0xfe | 0x01;
                    //            ^------------^   ^--^
                    //             OLD VALUES       NEW VALUE
                else
                    argb[1] = argb[1] & 0xfe;
                //            ^------------^
                //             OLD VALUES (NEW VALUE IS IMPLICITY 0)

                // Replace the current pixel with new values
                int newPixel = rgbaToPixel(argb[0], argb[1], argb[2], argb[3]);
                this.image.setRGB(i, j, newPixel);
                System.out.println(cnt + " After --  Pixel (" + i + "," + j + "): Alpha: " + argb[0] + ", Red: " + argb[1] + ", Green: " + argb[2] + ", Blue: " + argb[3]);
                System.out.println();

                // Return if done
                cnt++;
                if (bitMessage.length == cnt)
                    return;
            }
        }
    }

    private int[] pixelToRgba(int pixel) {
        // Parse
        int alpha = (pixel >> 24) & 0xff;
        int red = (pixel >> 16) & 0xff;
        int green = (pixel >> 8) & 0xff;
        int blue = (pixel) & 0xff;
        int[] retVal = {alpha, red, green, blue};
        return retVal;
    }

    private int rgbaToPixel(int alpha, int red, int green, int blue) {
        // Compile
        return ((alpha & 0xff) << 24) | ((red & 0xff) << 16) | ((green & 0xff) << 8) | (blue & 0xff);
    }

    public static void main(String[] args) throws IOException {
        SteganoEncode se = new SteganoEncode("/1_Kyoto.png", "Steganogram.png", "Steganography rules!");
    }
}
