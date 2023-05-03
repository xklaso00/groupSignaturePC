package cz.vut.feec.xklaso00.groupsignature.gui;

import cz.vut.feec.xklaso00.groupsignature.ModelViewHandle;
import cz.vut.feec.xklaso00.groupsignature.fileManaging.FileOfManager;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class RegisterWindow {
    private JPanel PanelMain;
    private JPasswordField passwordField1;
    private JPasswordField passwordField2;
    private JButton button1;
    private JLabel checkLabel;
    JFrame frame= new JFrame();
    public RegisterWindow(FileOfManager fileOfManager){
        frame.setTitle("Manager Register");
        frame.setLayout(new BorderLayout());
        JLabel background=new JLabel(new ImageIcon("background.png"));
        frame.add(background);

        background.setLayout(new GridLayout());
        background.add(PanelMain);
        PanelMain.setOpaque(false);
        //frame.add(PanelMain);
        frame.pack();
        frame.setSize(400,250);

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int code= ModelViewHandle.registerMan(fileOfManager,passwordField1.getPassword(),passwordField2.getPassword());
                if (code==0)
                    frame.dispose();
                if(code==-1)
                    checkLabel.setText("The passwords are not the same");
                else if(code==-2)
                    checkLabel.setText("Please enter a password");
            }
        });
    }
}
