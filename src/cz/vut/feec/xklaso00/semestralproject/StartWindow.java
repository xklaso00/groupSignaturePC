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
    private JLabel signLabel;
    private JLabel verLabel;
    private JLabel gmLabel;
    private JButton button1;


    private  ModelViewHandle modelViewHandle;

    public StartWindow(){
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        }
        catch (Exception e){
            System.out.println("Error loading UIManager");
        }
        try {
            frame.setLayout(new BorderLayout());
            JLabel background=new JLabel(new ImageIcon("background.png"));
            frame.add(background);
            //background.setSize(700,500);
            background.setLayout(new GridLayout());
            background.add(MainPanel);
            MainPanel.setOpaque(false);
            Panel1.setOpaque(false);
            Panel2.setOpaque(false);

        }catch (Exception e){
            System.out.println("Error in loading the background");
            frame.add(MainPanel);
        }

        managerButton.setFocusPainted(false);
        //frame.add(MainPanel);
        //frame.add(Panel1);
        //frame.add(Panel2);
        frame.pack();

        frame.setSize(700,500);
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
                modelViewHandle.signDocument(signLabel);
            }
        });
        verifierButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelViewHandle.checkSignature(verLabel);
            }
        });

        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String reeeee=FileManagerClass.chooseFile("e");
                System.out.println(reeeee);
                byte [] pdf=PDFManager.getContentBytesOfPDF(reeeee);
            }
        });
    }

}
