package org.owasp.dependencycheck.utils;

import org.apache.hc.client5.http.impl.classic.AbstractHttpClientResponseHandler;
import org.apache.hc.core5.http.HttpEntity;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;

class SaveToFileResponseHandler extends AbstractHttpClientResponseHandler<Void> {

    /**
     * The output path where the response content should be stored as a file
     */
    private final File outputPath;

    SaveToFileResponseHandler(File outputPath) {
        this.outputPath = outputPath;
    }

    @Override
    public Void handleEntity(HttpEntity responseEntity) throws IOException {
        try (InputStream in = responseEntity.getContent();
             ReadableByteChannel sourceChannel = Channels.newChannel(in);
             FileOutputStream fos = new FileOutputStream(outputPath);
             FileChannel destChannel = fos.getChannel()) {
            final ByteBuffer buffer = ByteBuffer.allocateDirect(8192);
            while (sourceChannel.read(buffer) != -1) {
                buffer.flip();
                destChannel.write(buffer);
                buffer.compact();
            }
        }
        return null;
    }
}