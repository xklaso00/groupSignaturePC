package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;

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
    public int InitializeConnection(){


        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = null;
            terminals = factory.terminals().list();
            System.out.println("Terminals: " + terminals);
            CardTerminal terminal = terminals.get(0);

            while (!terminal.isCardPresent()) ;
                // Connect wit the card, using supported protocol, for some reason T=0 not working
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
        } catch (CardException e) {
            e.printStackTrace();
        }


        return -1;
    }
    public boolean sendPublicParameters(ServerTwoPartyObject obj){
        byte[] com=Instructions.makeSetupCommand(obj);
        InitializeConnection();
        try {

            ResponseAPDU responseAPDU=channel.transmit(new CommandAPDU(com));
            byte[] byteResponse=null;
            byteResponse=responseAPDU.getBytes();
            System.out.println("I got back:" +Instructions.bytesToHex(byteResponse));
            card.disconnect(true);
            if(Instructions.isEqual(Instructions.getaOkay(),byteResponse)){
                return true;
            }
        } catch (CardException e) {
            e.printStackTrace();
        }
        return false;
    }
    public int userZKRequest(Server server){
        InitializeConnection();
        try {

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
                boolean secondProof=server.checkPKUser(userZK.getZets(),userZK.getE2(),userZK.getC2Goth(),userZK.geteClientHash(),userZK.getClientPubKey());
                System.out.println("is client NIZKPK legit "+secondProof);
                if(!secondProof) {
                    ResponseAPDU responseAPDU1=channel.transmit(new CommandAPDU(Instructions.getFAILEDZK()));
                    return -5;
                }
                //here we add the user to database of pkInvs for open Func
                server.saveUserKeyToFile(userZK.getClientPubKey(),userZK.getClientID());
                //we write out for test
                //server.getActiveManagerFile().writeOutUsersSaved();

                G1 e2=server.computePubManager(userZK.getE2());
                byte[] e2COM= Instructions.createE2COM(e2);
                System.out.println("Sending e2 ");
                //modded for watch remove for phone
                //InitializeConnection();


                ResponseAPDU responseAPDU1=channel.transmit(new CommandAPDU(e2COM));
                byteResponse=responseAPDU1.getBytes();
                System.out.println("Response for e2 is "+Instructions.bytesToHex(byteResponse));
                card.disconnect(true);
                System.out.println("DONE ON MY PART ");
                lastID=userZK.getClientID();


            }catch (Exception e){
                e.printStackTrace();
            }



        } catch (CardException e) {
            throw new RuntimeException(e);
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
    public int sendFileToSign(byte[] fileHash){
        int connectionInitialized=InitializeConnection();
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
            card.disconnect(true);
            byte[] SignObject= Arrays.copyOfRange(byteResponse,0,byteResponse.length-2);
            //should check the last 2 bytes here
            byte [] checkBytes=Arrays.copyOfRange(byteResponse,byteResponse.length-2,byteResponse.length);

            if(!(Instructions.isEqual(checkBytes,Instructions.getaOkay()))){
                System.out.println("Probably did nto get all bytes");
                return -6;
            }
            ByteArrayInputStream bis = new ByteArrayInputStream(SignObject);
            ObjectInputStream ois=new ObjectInputStream(bis);
            SignatureProof signatureProof= (SignatureProof) ois.readObject();
            G2 groupPublicKey=FileManagerClass.loadPublicKeyForGroup(signatureProof.groupID);
            if(groupPublicKey==null){
                System.out.println("Cannot load the key");
                return -4;
            }
            BigInteger hashBig=new BigInteger(fileHash);
            Fr hashFr=new Fr(hashBig.toString(10));
            boolean LegitSignature=Server.checkProof(signatureProof,hashFr,groupPublicKey);

            if(LegitSignature){
                System.out.println("SIG LEGIT");
                FileManagerClass.saveSignature(signatureProof);
                //add saving to file the signature
                return 0;
            }
            else {
                System.out.println("NOT LEGIT SIG");
                return -5;
            }


        } catch (Exception e) {
            e.printStackTrace();
            return -3;
        }


    }
}
