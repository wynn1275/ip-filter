package com.wynnn.ipfilter.common;

import org.junit.jupiter.api.Test;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.stream.IntStream;

public class CreateMillionIpScript {

    private int NUM_CREATE_IP = 30000000;

//    @Test
    public void givenWritingStringToFile_whenUsingPrintWriter_thenCorrect() throws IOException {
        FileWriter fileWriter = new FileWriter("manual-ip-denies-properties.yml");
        PrintWriter printWriter = new PrintWriter(fileWriter);
        printWriter.print("spring.profiles.active: release\n");
        printWriter.print("ip-filter.deny: \n");

        IntStream.range(1, NUM_CREATE_IP+1).forEach((i) -> {
            printWriter.printf("    - %s/32\n", longToIp(i));
        });
        printWriter.close();
    }

    private String longToIp(long ip) {

        return ((ip >> 24) & 0xFF) + "."
                + ((ip >> 16) & 0xFF) + "."
                + ((ip >> 8) & 0xFF) + "."
                + (ip & 0xFF);

    }
}
