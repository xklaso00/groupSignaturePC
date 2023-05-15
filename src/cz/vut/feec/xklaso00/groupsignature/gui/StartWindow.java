package cz.vut.feec.xklaso00.groupsignature.gui;

import cz.vut.feec.xklaso00.groupsignature.ModelViewHandle;
import cz.vut.feec.xklaso00.groupsignature.Server;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.NIZKPKFunctions;
import cz.vut.feec.xklaso00.groupsignature.fileManaging.FileManagerClass;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class StartWindow {

    JFrame frame= new JFrame("Group signature with two-party computation");
    private JPanel MainPanel;
    private JButton managerButton;
    private JButton clientButton;
    private JButton createManagerButton;
    private JButton verifierButton;
    private JLabel managerLabel;
    private JPanel Panel1;
    private JPanel Panel2;
    private JButton gmpOp;


    private ModelViewHandle modelViewHandle;

    public StartWindow(){
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        /*try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        }
        catch (Exception e){
            System.out.println("Error loading UIManager");
        }*/
        ImageIcon iconEnGMP=null;
        ImageIcon iconDisGMP=null;
        try {
            FileManagerClass.tryFiles();
            frame.setLayout(new BorderLayout());
            JLabel background=new JLabel(new ImageIcon("background.png"));
            frame.add(background);

            background.setLayout(new GridLayout());
            background.add(MainPanel);
            MainPanel.setOpaque(false);
            Panel1.setOpaque(false);
            Panel2.setOpaque(false);
            ImageIcon icon= new ImageIcon("files/icons/clientAppButton.png");
            clientButton.setIcon(icon);
            ImageIcon iconVer=new ImageIcon("files/icons/verifyAppButton.png");
            verifierButton.setIcon(iconVer);
            ImageIcon iconMan=new ImageIcon("files/icons/managerButton.png");
            managerButton.setIcon(iconMan);
            ImageIcon iconGen=new ImageIcon("files/icons/generateButton.png");
            createManagerButton.setIcon(iconGen);
            iconEnGMP=new ImageIcon("files/icons/enGMPbutton.png");
            iconDisGMP=new ImageIcon("files/icons/disGMPbutton.png");
            if(NIZKPKFunctions.isUseGMP()){
                gmpOp.setIcon(iconDisGMP);
            }
            else
                gmpOp.setIcon(iconEnGMP);

            if(icon!=null)
                clientButton.setText("");
            if(iconVer!=null)
                verifierButton.setText("");
            if(iconMan!=null)
                managerButton.setText("");
            if(iconGen!=null)
                createManagerButton.setText("");
            if(iconEnGMP!=null && iconDisGMP!=null)
                gmpOp.setText("");

        }catch (Exception e){
            System.out.println("Error in loading the background");
            frame.add(MainPanel);
        }

        managerButton.setFocusPainted(false);
        //frame.add(MainPanel);
        //frame.add(Panel1);
        //frame.add(Panel2);
        frame.pack();

        frame.setSize(800,500);
        frame.setLocationRelativeTo(null);

        frame.setVisible(true);
        modelViewHandle=new ModelViewHandle();
        if(NIZKPKFunctions.isUseGMP()){
            gmpOp.setText("Disable GMP");
        }
        createManagerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Server server=modelViewHandle.createServer();
                new RegisterWindow(server.getActiveManagerFile());

                managerLabel.setText("New manager with ID: "+modelViewHandle.getServer().getManagerID().toString(16)+" was created");
            }
        });
        managerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                /*String retString=modelViewHandle.createManagerWindow();
                if(!retString.equals(null)){
                    frame.dispose();
                }*/
                String path=FileManagerClass.chooseFile("Choose manager _keyEnc.ser file");
                new LoginWindow(path,frame);
            }
        });
        clientButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                //modelViewHandle.signDocument(signLabel);
                new UserWindow();
                frame.dispose();
            }
        });
        verifierButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //modelViewHandle.checkSignature(verLabel);
                new VerifierWindow();
                frame.dispose();
            }
        });


        ImageIcon finalIconDisGMP = iconDisGMP;
        ImageIcon finalIconEnGMP = iconEnGMP;
        gmpOp.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if(!NIZKPKFunctions.isUseGMP()){

                    System.loadLibrary("gmp_forJava");
                    if(NIZKPKFunctions.testGMP()!=0){
                        return;
                    }
                    System.out.println("GMP enabled");
                    NIZKPKFunctions.setUseGMP(true);

                    if(!(finalIconDisGMP ==null)) {
                        gmpOp.setIcon(finalIconDisGMP);
                    }else
                        gmpOp.setText("Disable GMP");
                }
                else{
                    NIZKPKFunctions.setUseGMP(false);
                    System.out.println("GMP disabled");
                    if(!(finalIconEnGMP ==null)){
                        gmpOp.setIcon(finalIconEnGMP);
                    }else
                        gmpOp.setText("Enable GMP");
                }
            }
        });
    }

}
