package cz.vut.feec.xklaso00.groupsignature.gui;

import cz.vut.feec.xklaso00.groupsignature.ModelViewHandle;
import cz.vut.feec.xklaso00.groupsignature.fileManaging.FileManagerClass;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class LoginWindow {
    JFrame frame= new JFrame();
    private JPanel PanelMain;
    private JPasswordField passwordField1;
    private JButton button1;
    private JLabel checklabel;

    public LoginWindow(String filePath,JFrame frameMain){
        frame.setTitle("Manager Login");
        JLabel background=new JLabel(new ImageIcon("background2.png"));
        frame.add(background);

        background.setLayout(new GridLayout());
        background.add(PanelMain);
        PanelMain.setOpaque(false);
        frame.pack();
        frame.setSize(350,200);

        frame.setLocationRelativeTo(null);
        frame.setVisible(true);


        button1.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int res=ModelViewHandle.loginManager(passwordField1.getPassword(),filePath);
                if (res==0) {
                    frame.dispose();
                    frameMain.dispose();
                }
                else if(res==-1){
                    checklabel.setText("Wrong password");
                }
                else{
                    checklabel.setText("Probably wrong file chosen");
                }
            }
        });
    }
}
