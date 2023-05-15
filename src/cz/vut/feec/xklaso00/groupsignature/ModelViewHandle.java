package cz.vut.feec.xklaso00.groupsignature;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G2;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.GroupSignatureFunctions;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.NIZKPKFunctions;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.ServerTwoPartyObject;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.SignatureProof;
import cz.vut.feec.xklaso00.groupsignature.fileManaging.FileManagerClass;
import cz.vut.feec.xklaso00.groupsignature.fileManaging.FileOfManager;
import cz.vut.feec.xklaso00.groupsignature.gui.ManagerWindow;

import javax.swing.*;
import java.math.BigInteger;
import java.util.*;

import static cz.vut.feec.xklaso00.groupsignature.cryptocore.GroupSignatureFunctions.checkSignatureWithPK;
import static java.lang.Thread.sleep;

public class ModelViewHandle {
    //private static char[] pass;
    //private static HashMap<String,byte[][]> passesHashes;
    //private static byte[] aesKey;
    private static byte[][] hashSaltAesKey;
    private Server server;
    private ServerTwoPartyObject toSend;
    //private static SwingWorker<Boolean, Void> workerSendPublic=null;
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
        String fileNameToLoad= FileManagerClass.chooseFile("Choose a manager file (_key.ser)");
        if(FileManagerClass.loadManagerFile(fileNameToLoad)==null)
            return null;
        else {
            server = new Server(fileNameToLoad);
            new ManagerWindow(server);
            return fileNameToLoad;
        }
    }
    public boolean runSetupForTwoParty(JLabel addUserLabel, JTextArea textArea,boolean reRunSetup){
        /*if(workerSendPublic!=null && !workerSendPublic.isDone()){
            System.out.println("Should kill worker");
            workerSendPublic.cancel(true);
        }*/
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
                else if(ret==4){
                    //we try to receive it one more time
                    ret=terminal.userZKRequest(server);
                    if(ret!=0)
                        return false;
                    else
                        return true;
                }
                else
                    return false;
            }
            // GUI can be updated from this method.
            protected void done() {
                boolean status;
                try {
                    status=get();
                    //workerSendPublic=null;
                    if(status) {
                        addUserLabel.setText("User "+terminal.getLastID().toString(16) +" added.");
                        fillTextAreaWithUsers(textArea);
                    }
                    else {
                        if(ret==-5){
                            addUserLabel.setText("Could not verify userZK");
                        } else if (ret==-2) {
                            addUserLabel.setText("Problem with the answer");
                        } else if (ret==-3) {
                            addUserLabel.setText("Could not initialize connection");
                        } else if (ret==-4) {
                            addUserLabel.setText("NFC error, run again");
                        } else
                            addUserLabel.setText("Something Went Wrong");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        };


        SwingWorker<Boolean, Void> workerSendPublic = new SwingWorker<Boolean, Void>() {
            int ret;
            @Override
            protected Boolean doInBackground() throws Exception {
                Terminal terminal=new Terminal();
                ret=terminal.sendPublicParameters(toSend);
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
                        addUserLabel.setText("Manager ZK sent, waiting for mobile...");
                        worker2.execute();
                    }
                    else {
                        if(ret==-1){
                            addUserLabel.setText("Something went wrong, try again...");
                        } else if (ret==-2) {
                            addUserLabel.setText("Mobile did not recognize the app");
                        } else if (ret==-3) {
                            addUserLabel.setText("No terminals found");
                        } else if (ret==-4) {
                            addUserLabel.setText("NFC exception, run again");
                        } else if (ret==-5) {
                            addUserLabel.setText("NFC transmission failed, run again");
                        }else {
                            addUserLabel.setText("Something went wrong, try again...");
                        }

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                    System.out.println("Thread got Killed");
                }
            }

        };


        SwingWorker<Boolean, Void> worker1 = new SwingWorker<Boolean, Void>() {
            @Override
            protected Boolean doInBackground() throws Exception {
                //we check that reRun is false, server got generated set-up and it has the two-party object
                if(!reRunSetup&&(server.isGotSetup())&& (server.getToSendStored()!=null)){
                    toSend=server.getToSendStored();
                    server.setE1(toSend.getE1());
                }//else we run it again
                else {
                    server.runSetUpOfPaillier();
                    toSend= NIZKPKFunctions.computeE1andZKManager(server.getKp(),server.getServerPrivateECKey(),server.getManagerID());
                    server.setE1(toSend.getE1());
                    server.setToSendStored(toSend);
                }
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
        byte[] fileHash=FileManagerClass.ChooseAndHashFile(GroupSignatureFunctions.genNinBigInt());
        if(fileHash==null) {
            label.setText("Error in choosing the file");
            return;
        }
        label.setText("Put phone on NFC reader to sign the document.");

        SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
            int returnCode;
            @Override
            protected Boolean doInBackground() throws Exception {
                returnCode=terminal.sendFileToSign(fileHash,false);
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
                        else if (returnCode==-7)
                            label.setText("Could not save to file");
                        else
                            label.setText("Something went wrong");

                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

        };
        worker.execute();

    }
    public void checkSignature(JLabel label,JLabel revokeLabel){
        byte[] hash=FileManagerClass.ChooseAndHashFile(GroupSignatureFunctions.genNinBigInt());
        SignatureProof sp=FileManagerClass.loadSignature(FileManagerClass.getLastPathOfPDF());
        long start=System.nanoTime();
        if(sp!=null){
            BigInteger hashBig=new BigInteger(hash);
            Fr hashFr=new Fr(hashBig.toString(10));
            G2 groupPublicKey=FileManagerClass.loadPublicKeyForGroup(sp.groupID);
            boolean isLegit= GroupSignatureFunctions.checkProof(sp,hashFr,groupPublicKey);
            HashSet<byte[]> revoked= FileManagerClass.loadRevokedUsers(sp.groupID);
            Iterator<byte[]> iterator = revoked.iterator();
            long revT=System.nanoTime();
            while(iterator.hasNext()){
                byte[] invKey=iterator.next();
                G2 invKeyG2=new G2();
                invKeyG2.deserialize(invKey);
                int revokeResult= checkSignatureWithPK(invKeyG2,sp.getSiAph(),sp.getSiDash());
                if(revokeResult==0){
                    System.out.println("This user is revoked");
                    revokeLabel.setText("Revoked User");
                    isLegit=false;
                    break;
                }
            }
            System.out.println("Revocation check for "+revoked.size()+" revoked users took "+(System.nanoTime()-revT)/1000+ " microS");
            if(isLegit){
                System.out.println("legit sig");
                System.out.println("Total time of check sig is  "+(System.nanoTime()-start)/1000000+" ms");
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
        String choose=FileManagerClass.choosePDFFile();

        SignatureProof sp=FileManagerClass.loadSignature(choose);
        if(sp==null)
            label.setText("No Signature found");
        long start=System.nanoTime();
        BigInteger userID= server.openSignature(sp);
        System.out.println("opening took  "+(System.nanoTime()-start)/1000+" microS");
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
    /*public static boolean loadPasses(){
        passesHashes=FileManagerClass.loadPasses();
        if (passesHashes==null){
            passesHashes=new HashMap<>();
            FileManagerClass.savePassword(passesHashes);
            return false;
        }
        else
            return true;
    }*/
    public static int registerMan(FileOfManager fileOfManager,char[] pass1,char []pass2){
        if(!Arrays.equals(pass1,pass2)){
            System.out.println("Not same password");
            return -1;
        }
        if(pass1.length<1){
            System.out.println("no password");
            return -2;
        }


        byte[] salt=FileManagerClass.generateSalt(16);
        byte[][] ars=FileManagerClass.hashPassword(pass1,salt);
        /*byte[][] passSalt=new byte[2][];
        passSalt[0]=ars[0];
        passSalt[1]=ars[1];
        System.out.println(Instructions.bytesToHex(passSalt[0]));
        System.out.println(Instructions.bytesToHex(passSalt[1]));*/
        //passesHashes.put(fileOfManager.getManagerID().toString(16),ars);
        String filename=FileManagerClass.saveManagerEncrypted(ars,fileOfManager);
        //FileManagerClass.savePassword(passesHashes);
        return 0;
    }
    public static int loginManager(char[] pass1, String fileName){
        /*int start = fileName.lastIndexOf("/") + 1; // find the last index of
        if (start==-1 || start==0)
            start = fileName.lastIndexOf("\\") + 1;
        System.out.println("START IS "+start);
        int end = fileName.indexOf("_"); // find the index of "_"
        String result = fileName.substring(start, end);
        System.out.println("theIDStringIS "+result);
        byte[][] HashAndSalt =passesHashes.get(result);
        byte[][] outputFromHashes=FileManagerClass.hashPassword(pass1,HashAndSalt[1]);
        if(!Arrays.equals(HashAndSalt[0],outputFromHashes[0])){
            System.out.println("probably wrong pass");
            return -1;
        }*/

        //aesKey=outputFromHashes[2];
        //pass=pass1;
        int check=FileManagerClass.checkPasswordForFile(fileName,pass1);
        if(check==0){
            hashSaltAesKey=FileManagerClass.getLastHashSaltAesKey();
            FileOfManager fileOfManager=FileManagerClass.loadManagerFileEnc(fileName,hashSaltAesKey[2]);
            Server server=new Server(fileOfManager);
            new ManagerWindow(server);
            return 0;
        }
        //hashSaltAesKey=outputFromHashes;
       else {
           System.out.println("wrong pass probably");
           return check;
        }


    }
    public Server getServer() {
        return server;
    }

    public ServerTwoPartyObject getToSend() {
        return toSend;
    }



    public static byte[][] getHashSaltAesKey() {
        return hashSaltAesKey;
    }
}
