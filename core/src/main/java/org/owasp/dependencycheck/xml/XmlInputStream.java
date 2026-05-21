package org.owasp.dependencycheck.xml;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.concurrent.NotThreadSafe;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Cleans up often very bad XML. Primarily, this will convert named HTM entities
 * into their HTM encoded Unicode code point representation.
 *
 * <ol>
 * <li>Strips leading white space</li>
 * <li>Recodes &amp;pound; etc to &amp;#...;</li>
 * <li>Recodes lone &amp; as &amp;amp;</li>
 * </ol>
 * <p>
 * This is a slightly modified (class/method rename) from an SO answer:
 * https://stackoverflow.com/questions/7286428/help-the-java-sax-parser-to-understand-bad-xml</p>
 *
 * @author https://stackoverflow.com/users/823393/oldcurmudgeon
 */
@NotThreadSafe
public class XmlInputStream extends FilterInputStream {

    /**
     * The logger.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(XmlInputStream.class);
    /**
     * The minimum length of characters to read.
     */
    private static final int MIN_LENGTH = 2;
    /**
     * Holder for everything we've read.
     */
    private final StringBuilder red = new StringBuilder();
    /**
     * Data that needs to be pushed back.
     */
    private final StringBuilder pushBack = new StringBuilder();
    /**
     * How much we've given them.
     */
    private int given = 0;
    /**
     * How much we've read.
     */
    private int pulled = 0;

    /**
     * Constructs a new XML Input Stream.
     *
     * @param in the base input stream
     */
    public XmlInputStream(InputStream in) {
        super(in);
    }

    /**
     * NB: This is a Troll length (i.e. it goes 1, 2, many) so 2 actually means
     * "at least 2"
     *
     * @return the length
     */
    public int length() {
        try {
            final StringBuilder s = read(MIN_LENGTH);
            pushBack.append(s);
            return s.length();
        } catch (IOException ex) {
            LOGGER.warn("Oops ", ex);
        }
        return 0;
    }

    /**
     * Read n characters.
     *
     * @param n the number of characters to read
     * @return the characters read
     * @throws IOException thrown when an error occurs
     */
    private StringBuilder read(int n) throws IOException {
        // Input stream finished?
        boolean eof = false;
        // Read that many.
        final StringBuilder s = new StringBuilder(n);
        while (s.length() < n && !eof) {
            // Always get from the pushBack buffer.
            if (pushBack.length() == 0) {
                // Read something from the stream into pushBack.
                eof = readIntoPushBack();
            }

            // Pushback only contains deliverable codes.
            if (pushBack.length() > 0) {
                // Grab one character
                s.append(pushBack.charAt(0));
                // Remove it from pushBack
                pushBack.deleteCharAt(0);
            }

        }
        return s;
    }

    /**
     * Might not actually push back anything but usually will.
     *
     * @return true if at end-of-file
     * @throws IOException thrown if there is an IO exception in the underlying
     * steam
     */
    private boolean readIntoPushBack() throws IOException {
        // File finished?
        boolean eof = false;
        // Next char.
        final int ch = in.read();
        if (ch >= 0) {
            // Discard whitespace at start?
            if (!(pulled == 0 && isWhiteSpace(ch))) {
                // Good code.
                pulled += 1;
                // Parse out the &stuff;
                if (ch == '&') {
                    // Process the &
                    readAmpersand();
                } else {
                    // Not an '&', just append.
                    pushBack.append((char) ch);
                }
            }
        } else {
            // Hit end of file.
            eof = true;
        }
        return eof;
    }

    /**
     * Deal with an ampersand in the stream.
     *
     * @throws IOException thrown if an unknown entity is encountered
     */
    private void readAmpersand() throws IOException {
        // Read the whole word, up to and including the ;
        final StringBuilder reference = new StringBuilder();
        int ch;
        // Should end in a ';'
        for (ch = in.read(); isAlphaNumeric(ch); ch = in.read()) {
            reference.append((char) ch);
        }
        // Did we tidily finish?
        if (ch == ';') {
            // Yes! Translate it into a &#nnn; code.
            final String code = XmlEntity.fromNamedReference(reference);
            if (code != null) {
                // Keep it.
                pushBack.append(code);
            } else {
                // invalid entity. Encode the & and append the sequence of chars.
                pushBack.append("&#38;").append(reference).append((char) ch);
            }
        } else {
            // Did not terminate properly!
            // Perhaps an & on its own or a malformed reference.
            // Either way, escape the &
            pushBack.append("&#38;").append(reference).append((char) ch);
        }
    }

    /**
     * Keep track of what we've given them.
     *
     * @param s the sequence of characters given
     * @param wanted the number of characters wanted
     * @param got the number of characters given
     */
    private void given(CharSequence s, int wanted, int got) {
        red.append(s);
        given += got;
        LOGGER.trace("Given: [" + wanted + "," + got + "]-" + s);
    }

    /**
     * Reads the next byte.
     *
     * @return the byte read
     * @throws IOException thrown when there is an problem reading
     */
    @Override
    public int read() throws IOException {
        final StringBuilder s = read(1);
        given(s, 1, 1);
        return s.length() > 0 ? s.charAt(0) : -1;
    }

    /**
     * Reads the next length of bytes from the stream into the given byte array
     * at the given offset.
     *
     * @param data the buffer to store the data read
     * @param offset the offset in the buffer to start writing
     * @param length the length of data to read
     * @return the number of bytes read
     * @throws IOException thrown when there is an issue with the underlying
     * stream
     */
    @Override
    public int read(@NonNull byte[] data, int offset, int length) throws IOException {
        final StringBuilder s = read(length);
        int n = 0;
        for (int i = 0; i < Math.min(length, s.length()); i++) {
            data[offset + i] = (byte) s.charAt(i);
            n += 1;
        }
        given(s, length, n);
        return n > 0 ? n : -1;
    }

    /**
     * To string implementation.
     *
     * @return a string representation of the data given and read from the
     * stream.
     */
    @Override
    public String toString() {
        final String s = red.toString();
        final StringBuilder h = new StringBuilder();
        // Hex dump the small ones.
        if (s.length() < 8) {
            for (int i = 0; i < s.length(); i++) {
                h.append(" ").append(Integer.toHexString(s.charAt(i)));
            }
        }
        return "[" + given + "]-\"" + s + "\"" + (h.length() > 0 ? " (" + h + ")" : "");
    }

    /**
     * Determines if the character is whitespace.
     *
     * @param ch the character to check
     * @return true if the character is whitespace; otherwise false
     */
    private boolean isWhiteSpace(int ch) {
        switch (ch) {
            case ' ':
            case '\r':
            case '\n':
            case '\t':
                return true;
            default:
                return false;
        }
    }

    /**
     * Checks if the given character is alpha-numeric.
     *
     * @param ch the character to check
     * @return true if the character is alpha-numeric; otherwise false.
     */
    private boolean isAlphaNumeric(int ch) {
        return ('a' <= ch && ch <= 'z')
                || ('A' <= ch && ch <= 'Z')
                || ('0' <= ch && ch <= '9');
    }
}
