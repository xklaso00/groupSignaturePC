package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.G1;
import com.herumi.mcl.G2;

import javax.smartcardio.*;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.util.Arrays;
import java.util.List;

public class Terminal {
    private Card card = null;
    private CardChannel channel=null;
    public boolean InitializeConnection(){


        try {
            TerminalFactory factory = TerminalFactory.getDefault();
            List<CardTerminal> terminals = null;
            terminals = factory.terminals().list();
            System.out.println("Terminals: " + terminals);
            CardTerminal terminal = terminals.get(0);

            try {
                while (!terminal.isCardPresent()) ;
                // Connect wit the card, using supported protocol, for some reason T=0 not working
                card = terminal.connect("*");
                System.out.println("Card: " + card);
                channel = card.getBasicChannel();
            } catch (CardException ce) {
                ce.printStackTrace();
            }

            ResponseAPDU response1 = channel.transmit(new CommandAPDU(Instructions.getAID()));
            byte[] byteResponse1 = null;
            byteResponse1 = response1.getBytes();
            System.out.println("Card response for choose AID command: " + Instructions.bytesToHex(byteResponse1));
            if(byteResponse1.length==2)
                return true;
        } catch (CardException e) {
            e.printStackTrace();
        }


        return false;
    }
    public void sendPublicParameters(ServerTwoPartyObject obj){
        byte[] com=Instructions.makeSetupCommand(obj);
        InitializeConnection();
        try {

            ResponseAPDU responseAPDU=channel.transmit(new CommandAPDU(com));
            byte[] byteResponse=null;
            byteResponse=responseAPDU.getBytes();
            System.out.println("I got back:" +Instructions.bytesToHex(byteResponse));
            card.disconnect(true);
        } catch (CardException e) {
            throw new RuntimeException(e);
        }
    }
    public int userZKRequest(Server server){
        InitializeConnection();
        try {

            byte[] com= Instructions.getCOMGIVEZKUSER();
            ResponseAPDU responseAPDU=channel.transmit(new CommandAPDU(com));
            byte[] byteResponse=null;
            byteResponse=responseAPDU.getBytes();

            System.out.println("I got back:" +Instructions.bytesToHex(byteResponse));

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
                G1 e2=server.computePubManager(userZK.getE2());
                byte[] e2COM= Instructions.createE2COM(e2);
                System.out.println("Sending e2 ");
                ResponseAPDU responseAPDU1=channel.transmit(new CommandAPDU(e2COM));
                byteResponse=responseAPDU.getBytes();
                card.disconnect(true);
                System.out.println("DONE ON MY PART ");


            }catch (Exception e){
                e.printStackTrace();
            }



        } catch (CardException e) {
            throw new RuntimeException(e);
        }
        return 0;
    }
}
