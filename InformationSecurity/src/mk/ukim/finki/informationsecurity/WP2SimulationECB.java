package mk.ukim.finki.informationsecurity;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

public class WP2SimulationECB {

    public static byte[][] makingBlocksFromPayloadData(byte[] payloadData) {
        byte[][] blocks;
        if(payloadData.length % 16 != 0) {
            blocks = new byte[(payloadData.length / 16) + 1][16];
        } else {
            blocks = new byte[payloadData.length / 16][16];
        }

        int iterator = 0;
        for(int i = 0; i < payloadData.length; i++) {
            for(int j=0; j<16; j++) {
                if(iterator != payloadData.length) {
                    blocks[i][j] = payloadData[iterator];
                    iterator=iterator+1;
                }else {
                    break;
                }
            }
            if(iterator == payloadData.length) {
                break;
            }
        }
        return blocks;
    }

    public static byte[] arrayCopyInterval(byte[] array, int startID, int endID) {
        byte[] newArray = new byte[endID - startID];
        int j = 0;
        for(int i=startID; i<endID; i++) {
            newArray[j] = array[i];
            j++;
        }
        return newArray;
    }

    public static EncryptedFrame encryptFrame(ClearTextFrame frame, String keySecret) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Integer iterator = 0;
        EncryptedFrame encryptedFrame = new EncryptedFrame();
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        byte [] key = keySecret.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        key = md.digest(key);
        key = Arrays.copyOf(key,16);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key,"AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec);
        byte [] finalIV = cipher.update(frame.getIV());
        encryptedFrame.setMIC(frame.getMIC());

        byte [] sourceAddress = arrayCopyInterval(frame.frameHeader.getSourceMACAddress(),0,16);
        byte [] destinationAddress = arrayCopyInterval(frame.frameHeader.getDestinationMACAddress(),0,16);
        iterator=0;

        for(byte b : sourceAddress)
        {
            finalIV[iterator] = (byte) ( b ^ finalIV[iterator]);
            iterator=iterator+1;
        }
        finalIV = cipher.update(finalIV);

        iterator=0;
        for(byte b : destinationAddress)
        {
            finalIV[iterator] = (byte) ( b ^ finalIV[iterator]);
            iterator=iterator+1;
        }
        finalIV = cipher.update(finalIV);

        byte [][] payloadData = makingBlocksFromPayloadData(frame.getPayloadData());
        for(byte[] block : payloadData){
            iterator=0;
            for(byte b : block){
                finalIV[iterator] = (byte) (b ^ finalIV[iterator]);
                iterator=iterator+1;
            }
            finalIV= cipher.doFinal(finalIV);
        }
    byte [] MIC = arrayCopyInterval(finalIV,0,8);
        encryptedFrame.setMIC(MIC);
        frame.setMIC(MIC);
    byte [] encryptedPayloadData;

        encryptedPayloadData = new byte[frame.getPayloadData().length];


    byte[] onlyOnceAndCounter = new byte[16];
    byte[] nonce  = arrayCopyInterval(frame.getIV(),0,13);
    byte[] counter = "000".getBytes();

    for(iterator=0;iterator<13;iterator++)
    {
        onlyOnceAndCounter[iterator] = nonce [iterator];
    }
    int m=0;
    for(int iterator2=13;iterator2<16;iterator2++){
        onlyOnceAndCounter[iterator2]= counter[m];
        m++;
    }
    byte [] newMIC = new byte[8];
    byte[] AESforMIC = arrayCopyInterval(cipher.doFinal(onlyOnceAndCounter),0,8);
    iterator=0;
    for(byte b: AESforMIC){
        newMIC[iterator] = (byte) (b ^ MIC[iterator]);
        iterator++;
    }

    encryptedFrame.setEncryptedMIC(newMIC);
        counter[0]++;
        counter[1]++;
        counter[2]++;

        int dolzhina =0;
        for(iterator=0;iterator<frame.getPayloadData().length;iterator++)
        {



            m=0;
            for(int k=13;k<16;k++){
                onlyOnceAndCounter[k]=counter[m++];
            }

            byte [] AESfinal = cipher.doFinal(onlyOnceAndCounter);
            for(int j=0;j<16;j++)
            {
                if(dolzhina==frame.getPayloadData().length){
                    break;
                }

                encryptedPayloadData[iterator] = (byte) (AESfinal[j] ^ frame.getPayloadData()[dolzhina]);
                dolzhina=dolzhina+1;
                if(j!=15){
                    iterator++;
                }
            }
            counter[0]++;
            counter[1]++;
            counter[2]++;
        }

        encryptedFrame.setFrameHeader(frame.getFrameHeader());
        encryptedFrame.setPayloadData(encryptedPayloadData);
        encryptedFrame.setIvParameterSpec(frame.ivParameterSpec);
        encryptedFrame.setIV(frame.IV);
    return encryptedFrame;
    }



    public static ClearTextFrame decryptFrame(EncryptedFrame frame, String keySecret) throws Exception {
        Integer iterator = 0;
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        byte [] key = keySecret.getBytes(StandardCharsets.UTF_8);
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        key = md.digest(key);
        key = Arrays.copyOf(key,16);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key,"AES");
        cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec);

        byte [] clearTextPayloadData;

        clearTextPayloadData = new byte[frame.getPayloadData().length];


        byte[] onlyOnceAndCounter = new byte[16];
        byte[] nonce  = arrayCopyInterval(frame.getIV(),0,13);
        byte[] counter = "000".getBytes();

        for(iterator=0;iterator<13;iterator++)
        {
            onlyOnceAndCounter[iterator] = nonce [iterator];
        }
        int m=0;
        for(int iterator2=13;iterator2<16;iterator2++){
            onlyOnceAndCounter[iterator2]= counter[m];
            m++;
        }


        counter[0]++;
        counter[1]++;
        counter[2]++;

        int dolzhina = 0;
        for(iterator=0;iterator<frame.getPayloadData().length;iterator++)
        {

            m=0;
            for(int k=13;k<16;k++){
                onlyOnceAndCounter[k]=counter[m];
                m++;
            }

            byte [] AESfinal = cipher.doFinal(onlyOnceAndCounter);
            for(int j=0;j<16;j++)
            {
                if(dolzhina==frame.getPayloadData().length){
                    break;
                }

                clearTextPayloadData[iterator] = (byte) (AESfinal[j] ^ frame.getPayloadData()[dolzhina]);
                dolzhina++;
                if(j!=15){
                    iterator++;
                }
            }
            counter[0]++;
            counter[1]++;
            counter[2]++;
        }

       ClearTextFrame clearTextFrame =
               new ClearTextFrame(new String(
                       clearTextPayloadData)
                       ,new String(frame.getFrameHeader().getSourceMACAddress())
                       ,new String(frame.getFrameHeader().getDestinationMACAddress())
               );
        clearTextFrame.setPayloadData(clearTextFrame.getPayloadData());
        clearTextFrame.setMIC(frame.getMIC());
        return clearTextFrame;
    }








}
