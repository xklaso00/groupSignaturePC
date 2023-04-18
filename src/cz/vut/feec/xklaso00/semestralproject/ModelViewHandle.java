package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G2;

import javax.swing.*;
import java.awt.*;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

import static java.lang.Thread.sleep;

public class ModelViewHandle {

    private Server server;
    private ServerTwoPartyObject toSend;
    public ModelViewHandle(){

    }

    public ModelViewHandle(Server server) {
        this.server = server;
    }

    public Server createServer(){
        server=new Server();
        return server;
    }
    public String createManagerWindow(){
        String fileNameToLoad=FileManagerClass.chooseFile("Choose a manager file (_key.ser)");
        if(FileManagerClass.loadManagerFile(fileNameToLoad)==null)
            return null;
        else {
            server = new Server(fileNameToLoad);
            new ManagerWindow(server);
            return fileNameToLoad;
        }
    }
    public boolean runSetupForTwoParty(JLabel addUserLabel, JTextArea textArea){

        SwingWorker<Boolean, Void> worker2 = new SwingWorker<Boolean, Void>() {
            int ret=-1;
            Terminal terminal;
            @Override
            protected Boolean doInBackground() throws Exception {
                sleep(2500);
                terminal=new Terminal();
                ret=-1;
                while(ret==-1) {
                    ret = terminal.userZKRequest(server);
                }
                if(ret==0)
                    return true;
                else
                    return false;
            }
            // GUI can be updated from this method.
            protected void done() {
                boolean status;
                try {
                    status=get();
                    if(status) {
                        addUserLabel.setText("User "+terminal.getLastID().toString(16) +" added.");
                        fillTextAreaWithUsers(textArea);
                    }
                    else {
                        addUserLabel.setText("Something Went Wrong");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        };


        SwingWorker<Boolean, Void> workerSendPublic = new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                Terminal terminal=new Terminal();
                return terminal.sendPublicParameters(toSend);

            }
            // GUI can be updated from this method.
            protected void done() {
                boolean status;
                try {
                    status=get();
                    if(status) {
                        addUserLabel.setText("Manager ZK sent, waiting for mobile...");
                        worker2.execute();
                    }
                    else {
                        addUserLabel.setText("Something went wrong, try again...");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        };


        SwingWorker<Boolean, Void> worker1 = new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                server.runSetUpOfPaillier();
                BigInteger e1= server.computeE1();
                BigInteger[] Zs=server.createZKIssuer();
                toSend=new ServerTwoPartyObject(server.getPaillierPublicKeyFromServer(),e1,Zs,server.getcGoth(),server.geteHash(),server.getManagerID());
                return true;
            }
            // GUI can be updated from this method.
            protected void done() {
                boolean status;
                try {
                    status=get();
                    if(status) {
                        addUserLabel.setText("Setup Generated, put phone on NFC Reader");
                        workerSendPublic.execute();

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        };
        worker1.execute();
        addUserLabel.setText("Generating Setup...wait please");

        return true;
    }
    public void revokeUser(String ID, JLabel label){
        if(ID.equals("")){
            label.setText("Insert ID please.");
            return;
        }
        BigInteger IDToRevoke=new BigInteger(ID,16);
        System.out.println("ID TO REVOKE IS "+IDToRevoke.toString(16));
        int gotBack=server.revokeUser(IDToRevoke);
        if(gotBack==0){
            label.setText("User "+ID+" revoked.");
        }
        else if(gotBack==-1){
            label.setText("User "+ID+" is not in the group.");
        }
        else if(gotBack==-2){
            label.setText("Error while saving the file");
        }
    }
    public void signDocument(JLabel label){
        Terminal terminal=new Terminal();
        byte[] fileHash=FileManagerClass.ChooseAndHashFile(WeakBB.genNinBigInt());
        label.setText("Put phone on NFC reader to sign the document.");

        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            int returnCode;
            @Override
            protected Boolean doInBackground() throws Exception {
                returnCode=terminal.sendFileToSign(fileHash);
                if (returnCode==0)
                    return true;
                else
                    return false;
            }
            // GUI can be updated from this method.
            protected void done() {
                boolean status;
                try {
                    status=get();
                    if(status) {
                        label.setText("Signature created.");
                    }
                    else {
                        if(returnCode==-2)
                            label.setText("Invalid APDU response for choose AID.");
                        else if(returnCode==-1)
                            label.setText("Card Error, do you have terminal connected?");
                        else if(returnCode==-3)
                            label.setText("Error in communication...");
                        else if(returnCode==-4)
                            label.setText("Error loading key for check");
                        else if(returnCode==-5)
                            label.setText("Not legit signature.");

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        };
        worker.execute();

    }
    public void checkSignature(JLabel label){
        byte[] hash=FileManagerClass.ChooseAndHashFile(WeakBB.genNinBigInt());
        SignatureProof sp=FileManagerClass.loadSignature(FileManagerClass.getLastPathOfPDF());
        if(sp!=null){
            BigInteger hashBig=new BigInteger(hash);
            Fr hashFr=new Fr(hashBig.toString(10));
            G2 groupPublicKey=FileManagerClass.loadPublicKeyForGroup(sp.groupID);
            boolean isLegit=Server.checkProof(sp,hashFr,groupPublicKey);
            if(isLegit){
                System.out.println("legit sig");
                label.setText("The signature is legit from group "+sp.groupID.toString(16));
            }
            else{
                System.out.println("NOT LEGIT SIG");
                label.setText("The signature is not legit.");
            }
        }
        else {
            System.out.println("COULD not load signature");
            label.setText("Could not load the signature.");
        }
    }
    public void openSignature(JLabel label){
        String choose=FileManagerClass.chooseFile("Choose pdf to open the signature of");
        SignatureProof sp=FileManagerClass.loadSignature(choose);
        BigInteger userID= server.openSignature(sp);
        if(userID==null)
            label.setText("The user is not in my group.");
        else
            label.setText("The signature was created by user: "+userID.toString(16));
    }
    public void fillTextAreaWithUsers(JTextArea textArea){
        textArea.setText("Users in group: \n");
        HashMap <BigInteger, byte[]> usersHashMap=server.getActiveManagerFile().getUserHashMap();
        for(Map.Entry<BigInteger, byte[]> set :
                usersHashMap.entrySet()){

                textArea.append(set.getKey().toString(16));
            HashSet hs=server.getRevokedUsers();
            Iterator<byte[]> iterator =hs.iterator();
            while(iterator.hasNext()){
                if(Instructions.isEqual(iterator.next(),set.getValue())){
                    textArea.append(" REVOKED");
                    break;
                }

            }
                /*if(server.getRevokedUsers().contains(set.getValue()))
                    textArea.append(" REVOKED");*/
                textArea.append("\n");
            }

    }
    public Server getServer() {
        return server;
    }

    public ServerTwoPartyObject getToSend() {
        return toSend;
    }
}
