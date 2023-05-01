package cz.vut.feec.xklaso00.groupsignature.gui;

import cz.vut.feec.xklaso00.groupsignature.ModelViewHandle;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class VerifierWindow {
    private JPanel MainPanel;
    private JButton verButton;
    private JButton backToMenuButton;
    private JLabel checkLabel;
    JFrame frame= new JFrame("Verifier App");
    ModelViewHandle modelViewHandle;

    public VerifierWindow(){
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        try {
            frame.setLayout(new BorderLayout());
            JLabel background=new JLabel(new ImageIcon("background.png"));
            frame.add(background);
            //background.setSize(700,500);
            background.setLayout(new GridLayout());
            background.add(MainPanel);
            MainPanel.setOpaque(false);

            ImageIcon icon= new ImageIcon("files/icons/verSigButton.png");
            verButton.setIcon(icon);
            ImageIcon iconBack=new ImageIcon("files/icons/buttonBackground.png");
            backToMenuButton.setIcon(iconBack);
            if(iconBack!=null)
                backToMenuButton.setText("");



        }catch (Exception e){
            System.out.println("Error in loading the background");
            frame.add(MainPanel);
        }
        frame.pack();

        frame.setSize(450,300);
        frame.setLocationRelativeTo(null);

        frame.setVisible(true);
        modelViewHandle=new ModelViewHandle();
        verButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelViewHandle.checkSignature(checkLabel);
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
