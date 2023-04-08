package cz.vut.feec.xklaso00.semestralproject;

import com.herumi.mcl.Mcl;

public class Main {



    static {
        System.loadLibrary("mcljava-x64");


    }
    public static void main(String[] args) {


        Mcl.SystemInit(Mcl.BN254);
        /*cz.vut.feec.xklaso00.semestralproject.Server server= new cz.vut.feec.xklaso00.semestralproject.Server();
        cz.vut.feec.xklaso00.semestralproject.Client client= new cz.vut.feec.xklaso00.semestralproject.Client();

        server.runSetUpOfPaillier();
        BigInteger e1= server.getE1();
        BigInteger e2= client.getE2(e1,server.getPaillierPublicKeyFromServer());
        G1 pubManager= server.computePubManager(e2);
        G1 pubUser= client.computeKeyFromManager(pubManager);
        Fr msg= new Fr(12345);
        client.computeModifiedSchnorrProof(msg);
        boolean legitProof= server.checkProof(client.getGtoR(),client.getSiAph(),client.getSiDash(),msg,client.getE(),client.getSr(),client.getSSki());
        System.out.println("legit sig? " +legitProof);*/
        MainWindow mainWindow=new MainWindow();
    }
}