package cz.vut.feec.xklaso00.semestralproject;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;

public class StartWindow {

    JFrame frame= new JFrame("Group signature with multi-party computation");
    private JPanel MainPanel;
    private JButton managerButton;
    private JButton clientButton;
    private JButton createManagerButton;
    private JButton verifierButton;
    private JLabel managerLabel;
    private JPanel Panel1;
    private JPanel Panel2;



    private  ModelViewHandle modelViewHandle;

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
        try {
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


            if(icon!=null)
                clientButton.setText("");
            if(iconVer!=null)
                verifierButton.setText("");
            if(iconMan!=null)
                managerButton.setText("");
            if(iconGen!=null)
                createManagerButton.setText("");

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
        createManagerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelViewHandle.createServer();
                managerLabel.setText("New manager with ID: "+modelViewHandle.getServer().getManagerID().toString(16)+" was created");
            }
        });
        managerButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String retString=modelViewHandle.createManagerWindow();
                if(!retString.equals(null)){
                    frame.dispose();
                }
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


    }

}
