package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.ExecutionException;

import static java.lang.Thread.sleep;

public class MainWindow {
    private JPanel MainPanel;
    private JButton button1;
    private JButton signButton;
    //private JTextField textField1;
    private JButton verifyButton;
    private JLabel labelMulti;
    private JTextArea textArea1;
    private JLabel sigLabel;
    private JLabel legitLabel;
    private JButton nfcSimulate;
    private JLabel goNFClabel1;
    private JButton loadManagerButton;
    private JLabel managerLoadText;
    private JButton nfcSign;
    private boolean computed=false;
    JFrame frame= new JFrame("Group signature with multi-party computation");
    Server server;
    Client client;
    long st;
    long et;
    SignatureProof signatureProof;
    public Fr hashMsg(String message){
        MessageDigest hashing;
        try {
            hashing= MessageDigest.getInstance("SHA-256");
            byte[] byteMsg=message.getBytes();
            hashing.update(byteMsg);
            byte [] hash= hashing.digest();
            BigInteger hashBig= new BigInteger(hash);
            hashBig= hashBig.mod(client.getN());
            Fr hashFrCut=new Fr(hashBig.toString(10));
            return hashFrCut;
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);

        }
    }

    public MainWindow(){
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.add(MainPanel);
        frame.pack();

        frame.setSize(700,300);
        frame.setLocationRelativeTo(null);

        frame.setVisible(true);
        //server=new Server();
        server=new Server("files/53763a7a_key.ser");
        client=new Client();



        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                long st=System.nanoTime();
                server.runSetUpOfPaillier();
                long et=System.nanoTime();
                System.out.println("Setup of Paillier took "+(et-st)/1000000+" ms");
                st=System.nanoTime();
                BigInteger e1= server.computeE1();
                et=System.nanoTime();
                System.out.println("E1 computation took "+(et-st)/1000000+" ms");

                BigInteger[] Zs=server.createZKIssuer();
                boolean ZKLegit=client.checkIssuerZK(server.getPaillierPublicKeyFromServer(),Zs,e1,server.getcGoth(),server.geteHash());
                System.out.println("IS server NIZKPK legit? "+ZKLegit);

                st=System.nanoTime();
                BigInteger e2= client.computeE2(e1,server.getPaillierPublicKeyFromServer());
                et=System.nanoTime();
                System.out.println("E2 computation took "+(et-st)/1000000+" ms");
                st=System.nanoTime();
                BigInteger Zets[]=client.computeUserZK(server.getPaillierPublicKeyFromServer(),e1);
                boolean secondProof=server.checkPKUser(Zets,e2,client.getC2Goth(),client.geteHashClient(),client.getPublicKeyUser());
                System.out.println("is client NIZKPK legit"+secondProof);
                G1 pubManager= server.computePubManager(e2);
                et=System.nanoTime();
                System.out.println("E2 decryption took "+(et-st)/1000000+" ms");
                G1 pubUser= client.computeKeyFromManager(pubManager);
                labelMulti.setText("Multi-party computation completed, ready for signing");
                computed=true;
            }
        });
        signButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!computed) {
                    sigLabel.setText("Run the multiparty computation first");
                    return;
                }
                String message= textArea1.getText();
                System.out.println("message: "+message);
                Fr hash=hashMsg(message);
                System.out.println("Hash of the message cut to n of the curve is "+hash.toString(16));
                st=System.nanoTime();
                signatureProof=client.computeModifiedSchnorrProof(hash);
                et=System.nanoTime();
                System.out.println("The signature took "+((et-st)/1000)+" ns");
                System.out.println("______________________________________________________________________________________");
                sigLabel.setText("Signature generated");
            }
        });
        verifyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String message= textArea1.getText();
                Fr hashOfTheMessage=hashMsg(message);
                st=System.nanoTime();
                boolean legitProof= server.checkProof(signatureProof,hashOfTheMessage,server.getManagerPublicKey());
                et=System.nanoTime();
                System.out.println("The verification took "+((et-st)/1000)+" ns");
                System.out.println("legit? "+legitProof);
                if(legitProof)
                    legitLabel.setText("The signature was verified successfully");
                else
                    legitLabel.setText("The signature could not be verified");
            }
        });
        nfcSimulate.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                server.runSetUpOfPaillier();
                BigInteger e1= server.computeE1();
                BigInteger[] Zs=server.createZKIssuer();
                ServerTwoPartyObject toSend=new ServerTwoPartyObject(server.getPaillierPublicKeyFromServer(),e1,Zs,server.getcGoth(),server.geteHash(),server.getManagerID());
                SwingWorker<Boolean, Void> worker2 = new SwingWorker<Boolean, Void>() {
                    @Override
                    protected Boolean doInBackground() throws Exception {
                        sleep(3000);
                        Terminal terminal=new Terminal();
                        int ret=-100;
                        while(ret<0) {
                            ret = terminal.userZKRequest(server);
                        }
                        return true;
                    }
                    // GUI can be updated from this method.
                    protected void done() {
                        boolean status;
                        try {
                            status=get();
                            if(status) {
                                goNFClabel1.setText("done2");
                            }
                            else
                                goNFClabel1.setText("ree");
                            return;
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        } catch (ExecutionException e) {
                            e.printStackTrace();
                        }
                    }

                };
                SwingWorker<Boolean, Void> worker = new SwingWorker<Boolean, Void>() {
                    @Override
                    protected Boolean doInBackground() throws Exception {
                        Terminal terminal=new Terminal();
                        terminal.sendPublicParameters(toSend);

                        return true;
                    }
                    // GUI can be updated from this method.
                    protected void done() {
                        boolean status;
                        try {
                            status=get();
                            if(status) {
                                goNFClabel1.setText("done1");
                                worker2.execute();
                            }
                            else
                                goNFClabel1.setText("ree");
                            return;
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        } catch (ExecutionException e) {
                            e.printStackTrace();
                        }
                    }

                };
                worker.execute();
                goNFClabel1.setText("reeee");


                //worker2.execute();

            }
        });
        loadManagerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String fileNameToLoad=FileManagerClass.chooseFile("Choose a manager file (_key.ser)");
                server=new Server(fileNameToLoad);

            }
        });
        nfcSign.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Terminal terminal=new Terminal();
                byte[] fileHash=FileManagerClass.hashFile(client.getN());
                terminal.sendFileToSign(fileHash);
            }
        });
    }
}
