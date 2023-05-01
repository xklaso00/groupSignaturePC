package cz.vut.feec.xklaso00.groupsignature.gui;

import cz.vut.feec.xklaso00.groupsignature.ModelViewHandle;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class UserWindow {
    private JPanel MainPanel;
    private JButton backToMenuButton;
    private JButton signAPDFButton;
    private JLabel signLabel;
    private JPanel panel1;
    JFrame frame= new JFrame("Client signing app");
    ModelViewHandle modelViewHandle;

    public UserWindow(){
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        /*try {
            for (UIManager.LookAndFeelInfo info : UIManager.getInstalledLookAndFeels()) {
                System.out.println(info.getName());
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
            //background.setSize(700,500);
            background.setLayout(new GridLayout());
            background.add(MainPanel);
            MainPanel.setOpaque(false);
            panel1.setOpaque(false);
            ImageIcon icon= new ImageIcon("files/icons/signButton.png");
            signAPDFButton.setIcon(icon);
            ImageIcon iconBack=new ImageIcon("files/icons/buttonBackground.png");
            backToMenuButton.setIcon(iconBack);
            if(iconBack!=null)
                backToMenuButton.setText("");
            //signAPDFButton.setFocusPainted(true);



        }catch (Exception e){
            System.out.println("Error in loading the background");
            frame.add(MainPanel);
        }

        //frame.add(MainPanel);
        frame.pack();

        frame.setSize(450,300);
        frame.setLocationRelativeTo(null);

        frame.setVisible(true);
        modelViewHandle=new ModelViewHandle();

        signAPDFButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelViewHandle.signDocument(signLabel);
            }
        });
        backToMenuButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new StartWindow();
                frame.dispose();
            }
        });
    }
}
