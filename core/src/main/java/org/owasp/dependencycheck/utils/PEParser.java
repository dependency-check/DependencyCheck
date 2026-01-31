/*******************************************************************************
 * This program and the accompanying materials
 * are made available under the terms of the Common Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/cpl-v10.html
 *
 * Contributors:
 *     Peter Smith
 *******************************************************************************/
package org.owasp.dependencycheck.utils;

import com.kichik.pecoff4j.COFFHeader;
import com.kichik.pecoff4j.DOSHeader;
import com.kichik.pecoff4j.DOSStub;
import com.kichik.pecoff4j.DebugDirectory;
import com.kichik.pecoff4j.ImageData;
import com.kichik.pecoff4j.OptionalHeader;
import com.kichik.pecoff4j.PE;
import com.kichik.pecoff4j.PESignature;
import com.kichik.pecoff4j.SectionData;
import com.kichik.pecoff4j.SectionTable;
import com.kichik.pecoff4j.io.DataEntry;
import com.kichik.pecoff4j.io.DataReader;
import com.kichik.pecoff4j.io.IDataReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * This includes a copy of {@link PE#read(IDataReader)} and a couple of private methods
 * with some added error handling to swallow EOFExceptions when reading certain sections of the file
 * to be a bit more lenient on some "corrupt" (or not fully handled) dlls, per
 * <a href="https://github.com/dependency-check/DependencyCheck/issues/2601">...</a>
 *
 * @see com.kichik.pecoff4j.io.PEParser#parse(File) 
 * @see PE#read(IDataReader)
 */
public class PEParser {
    private static final Logger LOGGER = LoggerFactory.getLogger(PEParser.class);

    public static PE parse(File file) throws IOException {
        try (FileInputStream is = new FileInputStream(file); DataReader dr = new DataReader(is)) {
            return read(dr, file.getPath());
        }
    }

    /**
     * Duplicates {@link PE#read(IDataReader)} with added error handling to swallow EOFExceptions to be more lenient
     * for certain file sections.
     * @see PE#read(IDataReader)
     */
    private static PE read(IDataReader dr, String context) throws IOException {
        PE pe = new PE();
        pe.setDosHeader(DOSHeader.read(dr));

        // Check if we have an old file type
        if (pe.getDosHeader().getAddressOfNewExeHeader() == 0
                || pe.getDosHeader().getAddressOfNewExeHeader() > 8192) {
            return pe;
        }

        pe.setStub(DOSStub.read(pe.getDosHeader(), dr));
        pe.setSignature(PESignature.read(dr));

        // Check signature to ensure we have a pe/coff file
        if (!pe.getSignature().isValid()) {
            return pe;
        }

        pe.setCoffHeader(COFFHeader.read(dr));
        pe.setOptionalHeader(OptionalHeader.read(dr));
        pe.setSectionTable(SectionTable.read(pe, dr));

        pe.set64(pe.getOptionalHeader().isPE32plus());

        // Now read the rest of the file
        DataEntry entry;
        while ((entry = pe.findNextEntry(dr.getPosition())) != null) {
            DataEntry finalEntry = entry;
            if (finalEntry.isSection) {
                SectionData.read(pe, finalEntry, dr);
            } else if (entry.isDebugRawData) {
                withEofSwallowing(() -> readDebugRawData(pe, finalEntry, dr), "debug raw data: " + context);
            } else {
                withEofSwallowing(() -> pe.getImageData().read(pe, finalEntry, dr), "image data: " + context);
            }
        }

        // Read any trailing data
        withEofSwallowing(() -> {
            byte[] tb = dr.readAll();
            if (tb.length > 0) {
                pe.getImageData().setTrailingData(tb);
            }
        }, "trailing data: " + context);

        return pe;
    }

    /**
     * Duplicates {@link PE#readDebugRawData(PE, DataEntry, IDataReader)} since it is private.
     * @see PE#readDebugRawData(PE, DataEntry, IDataReader)
     */
    private static void readDebugRawData(PE pe, DataEntry entry, IDataReader dr) throws IOException {
        // Read any preamble data
        ImageData id = pe.getImageData();
        byte[] pa = dr.readNonZeroOrNull(entry.pointer);
        if (pa != null) {
            id.setDebugRawDataPreamble(pa);
        }
        DebugDirectory dd = id.getDebug();
        byte[] b = new byte[dd.getSizeOfData()];
        dr.read(b);
        id.setDebugRawData(b);
    }

    private static void withEofSwallowing(IOExceptionThrower throwingRunnable, String errorContext) throws IOException {
        try {
            throwingRunnable.read();
        } catch (EOFException e) {
            LOGGER.debug("Error reading {}. Trying to continue...", errorContext, e);
        }
    }

    private interface IOExceptionThrower {
        void read() throws IOException;
    }
}
