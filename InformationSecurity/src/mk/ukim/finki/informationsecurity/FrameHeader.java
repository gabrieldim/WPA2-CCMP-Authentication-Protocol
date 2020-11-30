package mk.ukim.finki.informationsecurity;

import java.nio.charset.StandardCharsets;

public class FrameHeader {
    String SourceMACAddress;
    String DestinationMACAddress;

    public FrameHeader(String sourceMACAddress, String destinationMACAddress) throws Exception {
        SourceMACAddress = sourceMACAddress;
        DestinationMACAddress = destinationMACAddress;
    }

    public byte []  getSourceMACAddress() {
        return SourceMACAddress.getBytes(StandardCharsets.UTF_8);
    }

    public byte [] getDestinationMACAddress() {
        return DestinationMACAddress.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return " SourceMACAddress=" + SourceMACAddress + "\n" +
                " DestinationMACAddress=" + DestinationMACAddress;
    }
}
