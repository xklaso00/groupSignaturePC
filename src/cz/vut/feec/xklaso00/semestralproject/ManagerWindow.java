package cz.vut.feec.xklaso00.semestralproject;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import static java.lang.Thread.sleep;

public class ManagerWindow {
    private JPanel MainPanel;
    private JPanel panel1;
    private JPanel panel2;
    private JButton addUserButton;
    private JLabel managerIDLabel;
    private JButton revokeUserButton;
    private JButton openSignatureButton;
    private JLabel addUserLabel;
    private JButton backToMenuButton;
    private JTextField revokeField;
    private JLabel revokeLabel;
    private JLabel openLabel;
    private JTextArea textArea1;
    JFrame frame= new JFrame("Manager Window");
    ModelViewHandle modelViewHandle;
    public ManagerWindow(Server server){
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        try {
            frame.setLayout(new BorderLayout());
            JLabel background=new JLabel(new ImageIcon("background2.png"));
            frame.add(background);
            //background.setSize(700,500);
            background.setLayout(new GridLayout());
            background.add(MainPanel);
            MainPanel.setOpaque(false);
            panel1.setOpaque(false);
            panel2.setOpaque(false);


        }catch (Exception e){
            System.out.println("Error in loading the background");
            frame.add(MainPanel);
        }

        //frame.add(MainPanel);
        frame.pack();

        frame.setSize(650,400);
        frame.setLocationRelativeTo(null);

        frame.setVisible(true);
        modelViewHandle=new ModelViewHandle(server);
        managerIDLabel.setText(managerIDLabel.getText()+modelViewHandle.getServer().getManagerID().toString(16));
        modelViewHandle.fillTextAreaWithUsers(textArea1);
        textArea1.setEditable(false);



        backToMenuButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                new StartWindow();
                frame.dispose();
            }
        });
        addUserButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelViewHandle.runSetupForTwoParty(addUserLabel,textArea1);

            }

        });


        revokeUserButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String ID= revokeField.getText();
                modelViewHandle.revokeUser(ID,revokeLabel);

                modelViewHandle.fillTextAreaWithUsers(textArea1);

            }
        });
        openSignatureButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                modelViewHandle.openSignature(openLabel);
            }
        });
    }
}
