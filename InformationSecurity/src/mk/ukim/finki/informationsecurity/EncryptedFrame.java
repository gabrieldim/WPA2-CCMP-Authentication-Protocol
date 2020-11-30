package mk.ukim.finki.informationsecurity;

import javax.crypto.spec.IvParameterSpec;
import java.util.Arrays;
import java.util.Base64;

public class EncryptedFrame {
    private FrameHeader frameHeader;
    private byte [] IV;
    private byte [] payloadData;
    private byte [] encryptedMIC;
    private byte [] MIC;
    IvParameterSpec ivParameterSpec;

    public byte[] getMIC() {
        return MIC;
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

    public byte[] getEncryptedMIC() {
        return encryptedMIC;
    }

    public void setEncryptedMIC(byte[] encryptedMIC) {
        this.encryptedMIC = encryptedMIC;
    }

    public IvParameterSpec getIvParameterSpec() {
        return ivParameterSpec;
    }

    public void setIvParameterSpec(IvParameterSpec ivParameterSpec) {
        this.ivParameterSpec = ivParameterSpec;
    }

    @Override
    public String toString() {
      StringBuilder sb = new StringBuilder();
      sb.append(frameHeader.toString() + "\n PayloadData: " + Base64.getEncoder().encodeToString(payloadData) + "\n MIC: " + Base64.getEncoder().encodeToString(encryptedMIC));
      return sb.toString();
    }
}
