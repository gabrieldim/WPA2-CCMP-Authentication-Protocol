package mk.ukim.finki.informationsecurity;

import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class ClearTextFrame {
    byte [] IV = new byte[16];
    byte [] MIC;
    IvParameterSpec ivParameterSpec;
    FrameHeader frameHeader;
    byte [] payloadData;

    public ClearTextFrame(String payloadData, String SourceAddress, String DestinationAddress) throws Exception {
        generateInitialVector();
        frameHeader = new FrameHeader(SourceAddress,DestinationAddress);
        this.payloadData = payloadData.getBytes(StandardCharsets.UTF_8);
    }

    public void setMIC(byte[] MIC) {
        this.MIC = MIC;
    }

    public byte[] getIV() {
        return IV;
    }

    public void setIV(byte[] IV) {
        this.IV = IV;
    }

    public byte[] getMIC() {
        return MIC;
    }

    public IvParameterSpec getIvParameterSpec() {
        return ivParameterSpec;
    }

    public void setIvParameterSpec(IvParameterSpec ivParameterSpec) {
        this.ivParameterSpec = ivParameterSpec;
    }

    public FrameHeader getFrameHeader() {
        return frameHeader;
    }

    public void setFrameHeader(FrameHeader frameHeader) {
        this.frameHeader = frameHeader;
    }

    public byte[] getPayloadData() {
        return payloadData;
    }

    public void setPayloadData(byte[] payloadData) {
        this.payloadData = payloadData;
    }

    public String toString(){
        StringBuilder sb = new StringBuilder();
        sb.append(frameHeader.toString());
        sb.append("\n Payload Data: "  + new String(payloadData,StandardCharsets.UTF_8) +"\n MIC: " + Base64.getEncoder().encodeToString(MIC) );
        return sb.toString();
    }

    public void generateInitialVector(){
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(IV);
        this.ivParameterSpec = new IvParameterSpec(IV);
    }

}
