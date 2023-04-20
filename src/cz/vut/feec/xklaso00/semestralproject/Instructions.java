package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.G1;

import java.io.*;
import java.math.BigInteger;

public class Instructions {

    private static byte[] AID = new byte[]{(byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xA4, // INS	- Instruction - Instruction code
            (byte)0x04, // P1	- Parameter 1 - Instruction parameter 1
            (byte)0x00, // P2	- Parameter 2 - Instruction parameter 2
            (byte)0x07, // Lc field	- Number of bytes present in the data field of the command
            (byte)0xF0, (byte)0x20, (byte)0x33, (byte)0x44, (byte)0x88, (byte)0x66, (byte)0x55, // NDEF Tag Application name
            (byte)0x00 };
    private static byte [] COM1 = new byte[]{(byte)0x80, //WITH THIS COMMAND WE SEND SETUP, E1 AND ZK
            (byte)0x01,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00};
    private static byte [] COMGIVEZKUSER = new byte[]{(byte)0x80, //with this command we want the user to give us his zk and e2
            (byte)0x02,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00,
            (byte)0xFF};
    private static byte [] COME2 = new byte[]{(byte)0x80, //WITH THIS COMMAND WE SEND SETUP, E1 AND ZK
            (byte)0x03,
            (byte)0x00,
            (byte)0x00,
            };
    private static final byte[] SIGNTHISCOMMAND=new byte[]{(byte)0x80, //WITH THIS COMMAND we send hash of file to sign
            (byte)0x04,
            (byte)0x00,
            (byte)0x00,
    };
    private static byte [] FAILEDZK = new byte[]{(byte)0x80, //with this command we want the user to give us his zk and e2
            (byte)0x66,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00,
            (byte)0x00};
    private static byte[] A_OKAY ={ (byte)0x90,
            (byte)0x00};
    private static byte[] NOT_YET ={ (byte)0xFF,
            (byte)0xFF};
    public static byte[] getAID() {
        return AID;
    }
    static String bytesToHex(byte[] bytes) {

        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    public static boolean isEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    public static byte[] makeSetupCommand(ServerTwoPartyObject pk){
        ByteArrayOutputStream bStream = new ByteArrayOutputStream();
        try {
            ObjectOutputStream oStream = new ObjectOutputStream( bStream );
            oStream.writeObject (pk);
            byte[] byteVal = bStream. toByteArray();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            outputStream.write(COM1);
            int lenOfData=byteVal.length;
            //String hexLen=Integer.toHexString(lenOfData);
            BigInteger bigInt = new BigInteger(String.valueOf(lenOfData),10);
            //bigInt=bigInt.add(new BigInteger("8",10));
            byte[] byteLen=bigInt.toByteArray();
            outputStream.write(byteLen);

            //System.out.println("byteValOfObject is"+Instructions.bytesToHex(byteVal));
            //System.out.println("pk len is"+lenOfData);
            outputStream.write(byteVal);
            outputStream.write((byte)0x20);
            outputStream.write((byte)0x20);
            byte [] completeCommand=outputStream.toByteArray();

            //System.out.println("n is"+pk.getN());
            return completeCommand;

        } catch (IOException e) {
            e.printStackTrace();

        }


        return null;
    }
    public static byte[] createE2COM(G1 e2){
        byte[] e2bytes=e2.serialize();
        ByteArrayOutputStream bo=new ByteArrayOutputStream();
        try {
            bo.write(COME2);
            int lenOfe2=e2bytes.length;
            BigInteger lenBig=(new BigInteger(String.valueOf(lenOfe2)));
            byte[] lenOfData=lenBig.toByteArray();
            bo.write(lenOfData);
            bo.write(e2bytes);
            bo.write((byte)0x00);
            byte []command=bo.toByteArray();
            return command;

        } catch (IOException e) {
            System.out.println("Error in createE2COM");
            e.printStackTrace();
        }
        return null;

    }
    public static byte[] makeSignFileCommand(byte[] hash){
        ByteArrayOutputStream bo=new ByteArrayOutputStream();
        try {
            bo.write(SIGNTHISCOMMAND);
            int lenOfHash=hash.length;
            BigInteger lenBig=new BigInteger(String.valueOf(lenOfHash));
            byte[] lenOfData=lenBig.toByteArray();
            bo.write(lenOfData);
            bo.write(hash);
            bo.write((byte)0x00);
            byte [] com=bo.toByteArray();
            return com;

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static byte[] getCOMGIVEZKUSER() {
        return COMGIVEZKUSER;
    }

    public static byte[] getaOkay() {
        return A_OKAY;
    }

    public static byte[] getNotYet() {
        return NOT_YET;
    }

    public static byte[] getFAILEDZK() {
        return FAILEDZK;
    }
}
