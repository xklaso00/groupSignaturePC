package cz.vut.feec.xklaso00.groupsignature;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.*;
import cz.vut.feec.xklaso00.groupsignature.fileManaging.FileManagerClass;

import javax.smartcardio.*;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import static java.lang.Thread.sleep;

public class Terminal {
    private Card card = null;
    private CardChannel channel=null;
    private BigInteger lastID;
    private static long totalStart;
    private static int timeChange=0;
    public int InitializeConnection(){

        CardTerminal terminal;
        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = null;
            try {
                terminals = factory.terminals().list();
                System.out.println("Terminals: " + terminals);
                terminal = terminals.get(0);
            }catch (Exception te){
                te.printStackTrace();
                return -3;
            }



            while (!terminal.isCardPresent()) ;
                // Connect wit the card, using supported protocol, for some reason T=0 not working
            if(((timeChange)%2)==0)
                totalStart=System.nanoTime();
            timeChange++;
            card = terminal.connect("*");
            System.out.println("Card: " + card);
            channel = card.getBasicChannel();

            ResponseAPDU response1 = channel.transmit(new CommandAPDU(Instructions.getAID()));
            byte[] byteResponse1 = null;
            byteResponse1 = response1.getBytes();
            System.out.println("Card response for choose AID command: " + Instructions.bytesToHex(byteResponse1));
            if(Instructions.isEqual(byteResponse1,Instructions.getaOkay()))
                return 0;
            else
                return -2;
        } catch (Exception e) {
            e.printStackTrace();

        }


        return -1;
    }
    public int sendPublicParameters(ServerTwoPartyObject obj){

        byte[] com=Instructions.makeSetupCommand(obj);
        System.out.println("The command is this long" +com.length);
        int init=InitializeConnection();
        if(!(init==0)){
            return init;
        }
        try {

            long start=System.nanoTime();
            ResponseAPDU responseAPDU=channel.transmit(new CommandAPDU(com));
            byte[] byteResponse=null;
            byteResponse=responseAPDU.getBytes();
            System.out.println("I got back:" +Instructions.bytesToHex(byteResponse));
            System.out.println("To send the parameters and get ok took "+(System.nanoTime()-start)/1000000+" ms");
            card.disconnect(true);
            if(Instructions.isEqual(Instructions.getaOkay(),byteResponse)){
                return 0;
            }
        } catch (CardException e) {
            e.printStackTrace();
            return -4;
        }
        return -5;
    }
    public int userZKRequest(Server server){
        int init=InitializeConnection();
        if(!(init==0)){
            System.out.println("could not connect to the app");
            return -3;
        }
        try {
            long fcStart=System.nanoTime();
            byte[] com= Instructions.getCOMGIVEZKUSER();
            ResponseAPDU responseAPDU=channel.transmit(new CommandAPDU(com));
            byte[] byteResponse=null;
            byteResponse=responseAPDU.getBytes();

            //System.out.println("I got back:" +Instructions.bytesToHex(byteResponse));

            if(Instructions.isEqual(Instructions.getNotYet(),byteResponse)){
                return -1;
            }

            byte[] zkObject= Arrays.copyOfRange(byteResponse,0,byteResponse.length-2);
            //should check the last 2 bytes here
            byte [] checkBytes=Arrays.copyOfRange(byteResponse,byteResponse.length-2,byteResponse.length);
            if(!(Instructions.isEqual(checkBytes,Instructions.getaOkay()))){
                System.out.println("Probably did nto get all bytes");
                return -2;
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(zkObject);
            try {
                ObjectInputStream ois =new ObjectInputStream(bis);
                UserZKObject userZK=(UserZKObject) ois.readObject();
                //boolean secondProof=server.checkPKUser(userZK.getZets(),userZK.getE2(),userZK.getC2Goth(),userZK.geteClientHash(),userZK.getClientPubKey());
                long start=System.nanoTime();
                boolean secondProof= NIZKPKFunctions.checkPKUser(userZK.getZets(),userZK.getE2(),userZK.getC2Goth(),userZK.geteClientHash(),userZK.getClientPubKey(),server.getE1(),server.getN(),server.getKp());
                System.out.println("Check Client proof took "+(System.nanoTime()-start)/1000000+" ms");
                System.out.println("is client NIZKPK legit "+secondProof);
                if(!secondProof) {
                    ResponseAPDU responseAPDU1=channel.transmit(new CommandAPDU(Instructions.getFAILEDZK()));
                    return -5;
                }
                //here we add the user to database of pkInvs for open Func

                //we write out for test
                //server.getActiveManagerFile().writeOutUsersSaved();
                start=System.nanoTime();
                G1 e2=NIZKPKFunctions.computeSigningKeyRandomized(userZK.getE2(),server.getKp(),server.getN());
                System.out.println("e2 dec took "+(System.nanoTime()-start)/1000000+" ms");
                byte[] e2COM= Instructions.createE2COM(e2);
                System.out.println("Sending e2 ");
                //modded for watch remove for phone
                InitializeConnection();


                ResponseAPDU responseAPDU1=channel.transmit(new CommandAPDU(e2COM));
                byteResponse=responseAPDU1.getBytes();
                System.out.println("Response for e2 is "+Instructions.bytesToHex(byteResponse));
                card.disconnect(true);
                System.out.println("Total time of the function checkPk and decE2 etc is  "+(System.nanoTime()-fcStart)/1000000+" ms");
                System.out.println("Total time with pauses is  "+(System.nanoTime()-totalStart)/1000000+" ms");
                server.saveUserKeyToFile(userZK.getClientPubKey(),userZK.getClientID());
                System.out.println("DONE ON MY PART ");
                lastID=userZK.getClientID();


            }catch (Exception e){
                e.printStackTrace();
                return -4;
            }



        } catch (CardException e) {
            e.printStackTrace();
            System.out.println("Problem with NFC, try again");

            try {
                ResponseAPDU responseAPDU1=channel.transmit(new CommandAPDU(Instructions.getFAILEDNFC()));
                card.disconnect(true);
            } catch (CardException ex) {
               e.printStackTrace();
            }
            return -4;
        }
        return 0;
    }

    public BigInteger getLastID() {
        if(!lastID.equals(null))
            return lastID;
        else
            return BigInteger.ZERO;
    }

    //pass the hash of the file modded with n
    public int sendFileToSign(byte[] fileHash,boolean checkSig){

        int connectionInitialized=InitializeConnection();
        long comStart=System.nanoTime();
        if(connectionInitialized!=0)
            return connectionInitialized;
        byte[] fileCom=Instructions.makeSignFileCommand(fileHash);
        try {
            boolean isItYet=false;
            byte[] byteResponse=null;
            while (!isItYet){
                ResponseAPDU responseAPDU=channel.transmit(new CommandAPDU(fileCom));
                byteResponse=responseAPDU.getBytes();
                if(Instructions.isEqual(byteResponse,Instructions.getNotYet())){
                    isItYet=false;
                    sleep(30);
                }
                else
                    isItYet=true;
            }
            //ResponseAPDU responseAPDU=channel.transmit(new CommandAPDU(fileCom));
            //byte[] byteResponse=responseAPDU.getBytes();
            System.out.println("Total sign time with coms is "+(System.nanoTime()-comStart)/1000000+" ms");
            card.disconnect(true);
            byte[] SignObject= Arrays.copyOfRange(byteResponse,0,byteResponse.length-2);
            //should check the last 2 bytes here
            byte [] checkBytes=Arrays.copyOfRange(byteResponse,byteResponse.length-2,byteResponse.length);

            if(!(Instructions.isEqual(checkBytes,Instructions.getaOkay()))){
                System.out.println("Probably did not get all bytes");
                return -6;
            }
            ByteArrayInputStream bis = new ByteArrayInputStream(SignObject);
            ObjectInputStream ois=new ObjectInputStream(bis);
            SignatureProof signatureProof= (SignatureProof) ois.readObject();
            if(checkSig) {
                G2 groupPublicKey = FileManagerClass.loadPublicKeyForGroup(signatureProof.groupID);
                if (groupPublicKey == null) {
                    System.out.println("Cannot load the key");
                    return -4;
                }
                BigInteger hashBig = new BigInteger(fileHash);
                Fr hashFr = new Fr(hashBig.toString(10));
                boolean LegitSignature = GroupSignatureFunctions.checkProof(signatureProof, hashFr, groupPublicKey);

                if (LegitSignature) {
                    System.out.println("SIG LEGIT");
                    FileManagerClass.saveSignature(signatureProof);
                    //add saving to file the signature
                    return 0;
                } else {
                    System.out.println("NOT LEGIT SIG");
                    return -5;
                }
            }
            else {
                System.out.println("Saving Sig Without Check");
                int saveRet=FileManagerClass.saveSignature(signatureProof);
                System.out.println("Total sign time with save is "+(System.nanoTime()-comStart)/1000000+" ms");
                if(saveRet==-1){
                    return -7;
                }
                return 0;
            }

        } catch (Exception e) {
            e.printStackTrace();
            return -3;
        }


    }
}
