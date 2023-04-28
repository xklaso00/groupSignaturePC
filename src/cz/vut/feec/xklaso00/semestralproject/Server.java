package cz.vut.feec.xklaso00.semestralproject;


import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;

public class Server {
    String TAG= "TimeStamps";
    private BigInteger n;
    private PaillierKeyPair kp;
    private BigInteger r;
    private BigInteger rDash;
    private BigInteger serverPrivateECKey ;
    private G1 pubManager;
    private Fr ManKey;
    private BigInteger e1;
    private BigInteger cGoth;
    private boolean useGMP=false;
    private G2 managerPublicKey;
    private BigInteger managerID;
    private BigInteger eHash;
    private FileOfManager activeManagerFile;
    private HashSet<byte[]> revokedUsers;
    //constructor for creating new manager
    public Server(){
        SecureRandom random=new SecureRandom();
        serverPrivateECKey=new BigInteger(254,random);
       // serverPrivateECKey = new BigInteger("216be04bcef01b36dc52814b38963f028e5d414856e467ebd0c069efdce5fb4a",16);

        n=new BigInteger("2523648240000001BA344D8000000007FF9F800000000010A10000000000000D",16);
        serverPrivateECKey=serverPrivateECKey.mod(n);
        ManKey= new Fr(serverPrivateECKey.toString(),10);
        managerID=new BigInteger(32,random);
        FileOfManager manFile=new FileOfManager(serverPrivateECKey,managerID);
        String managerFileName=FileManagerClass.saveManagerKey(manFile);
        managerPublicKey=new G2();
        Mcl.mul(managerPublicKey,WeakBB.getG2(),ManKey);
        FileOfGroup fileOfGroup=new FileOfGroup(managerID,managerPublicKey);
        String fileName=FileManagerClass.saveGroupCertToFile(fileOfGroup);
        activeManagerFile=manFile;
        revokedUsers=new HashSet<>();
        FileManagerClass.saveRevokedToFile(managerID,revokedUsers);


    }
    //constructor with loading manager file
    public Server(String managerFileName){
        FileOfManager manFile=FileManagerClass.loadManagerFile(managerFileName);
        serverPrivateECKey=manFile.getPrivateKey();
        n=new BigInteger("2523648240000001BA344D8000000007FF9F800000000010A10000000000000D",16);
        ManKey= new Fr(serverPrivateECKey.toString(),10);
        System.out.println("mankey is"+ManKey.toString());
        managerID = manFile.getManagerID();
        managerPublicKey=new G2();
        Mcl.mul(managerPublicKey,WeakBB.getG2(),ManKey);
        activeManagerFile=manFile;
        //load revokedUsers here
        revokedUsers=FileManagerClass.loadRevokedUsers(managerID);

    }

    public PaillierKeyPair runSetUpOfPaillier(){
        GothGroup gothGroup=FileManagerClass.loadGothParameters();
        kp= new PaillierKeyPair(4561,gothGroup);
        return kp;
    }

    public BigInteger computeE1(){
        r= PaillierFunctions.getRandom(kp.getPaillierPrivateKey().getPhi().bitLength(),kp.getPaillierPrivateKey().getPhi());
        e1= PaillierFunctions.computeE1(kp.getPaillierPublicKey(),serverPrivateECKey,r);
        computeCGoth();
        return e1;
    }
    public BigInteger computeCGoth(){
        //I modified this to be NGoth not PhiNGoth
        rDash=PaillierFunctions.getRandom(kp.getPaillierPublicKey().getNGoth().bitLength(),kp.getPaillierPublicKey().getNGoth());
        cGoth=kp.getPaillierPublicKey().getGGoth().modPow(serverPrivateECKey,kp.getPaillierPublicKey().getNGoth());
        BigInteger mid= kp.getPaillierPublicKey().getHGoth().modPow(rDash,kp.getPaillierPublicKey().getNGoth());
        cGoth=cGoth.multiply(mid);
        cGoth=cGoth.mod(kp.getPaillierPublicKey().getNGoth());

        return  cGoth;
    }

    public BigInteger[] createZKIssuer(){
        PaillierPublicKey pubK=kp.getPaillierPublicKey();
        PaillierPrivateKey privK=kp.getPaillierPrivateKey();

        BigInteger rho1=PaillierFunctions.getRandom(pubK.getNGoth().bitLength(),pubK.getNGoth());
        BigInteger rho2=PaillierFunctions.getRandom(pubK.getNn().bitLength(),pubK.getNn());
        BigInteger rho3=PaillierFunctions.getRandom(pubK.getNGoth().bitLength(),pubK.getNGoth());

        BigInteger t1=myModPow(pubK.getH(),rho1,pubK.getNn());
        BigInteger mid1=myModPow(pubK.getG(),rho2,pubK.getNn());
        t1=t1.multiply(mid1);
        t1=t1.mod(pubK.getNn());
        BigInteger t2=myModPow(pubK.getGGoth(),rho1,pubK.getNGoth());
        mid1=myModPow(pubK.getHGoth(),rho3,pubK.getNGoth());
        t2=t2.multiply(mid1);
        t2=t2.mod(pubK.getNGoth());
        eHash=hashTs(t1,t2);

        //lets not mod since it wont do anything and it did not work in client
        BigInteger [] Zs=new BigInteger[3];
        BigInteger z1= eHash.multiply(serverPrivateECKey);
        z1=z1.add(rho1);
        z1=z1.mod(pubK.getNGoth());

        BigInteger z2=eHash.multiply(r);
        z2=z2.add(rho2);
        z2=z2.mod(pubK.getNn());

        BigInteger z3=eHash.multiply(rDash);
        z3=z3.add(rho3);
        //z3=z3.mod(pubK.getNGoth());

        Zs[0]=z1;
        Zs[1]=z2;
        Zs[2]=z3;
        //Log.i(TAG,"t1  "+t1.toString());
        //Log.i(TAG,"t2  "+t2.toString());
        return Zs;
    }

    public BigInteger hashTs(BigInteger t1, BigInteger t2){
        try {
            MessageDigest hashing = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write(t1.toByteArray());
            outputStream.write(t2.toByteArray());
            byte[] chained= outputStream.toByteArray();
            hashing.update(chained);
            byte [] hash= hashing.digest();
            BigInteger hashBig= new BigInteger(hash);
            return hashBig;
        }
        catch (Exception ex){
            ex.printStackTrace();
            return null;
        }
    }

    public boolean checkPKUser(BigInteger[] Zets,BigInteger e2,BigInteger c2Goth,BigInteger eClientHash, G2 clientPubKey){

        PaillierPublicKey pubK=kp.getPaillierPublicKey();
        BigInteger nn=pubK.getNn();
        BigInteger nGoth=pubK.getNGoth();

        BigInteger alpha=myModPow(pubK.getH(),pubK.getnHalf(),nn);
        alpha=alpha.modInverse(nn);
        alpha=alpha.multiply(e1).mod(nn);
        BigInteger beta=myModPow(pubK.getH(),n,nn);

        BigInteger zS=Zets[0];
        BigInteger z1=Zets[1];
        BigInteger z2=Zets[2];
        BigInteger zU=Zets[3];
        BigInteger zGoth=Zets[4];
        BigInteger zAph=Zets[5];
        //Log.i(TAG,"Zs? "+zS.toString());

        //c1 comp
        BigInteger c1=myModPow(alpha,z1,nn);
        BigInteger help=myModPow(pubK.getH(),zAph,nn);
        c1=c1.multiply(help);
        help=myModPow(beta,z2,nn);
        c1=c1.multiply(help);
        help=myModPow(pubK.getG(),zGoth,nn);
        c1=c1.multiply(help);
        help=myModPow(pubK.getH(),pubK.getnHalf(),nn);
        help=help.modInverse(nn);
        help=help.multiply(e2).mod(nn);
        help=myModPow(help,eClientHash,nn);
        help=help.modInverse(nn);
        c1=c1.multiply(help).mod(nn);

        //c2 comp
        BigInteger c2=myModPow(pubK.getGGoth(),zS,nGoth);
        help=myModPow(pubK.getHGoth(),zGoth,nGoth);
        c2=c2.multiply(help);
        help=myModPow(c2Goth,eClientHash,nGoth);
        help=help.modInverse(nGoth);
        c2=c2.multiply(help).mod(nGoth);

        //c3 comp
        BigInteger c3=myModPow(c2Goth,z1,nGoth);
        help=pubK.getGGoth().modInverse(nGoth);
        help=myModPow(help,zAph,nGoth);
        c3=c3.multiply(help);
        help=myModPow(pubK.getHGoth(),zU,nGoth);
        c3=c3.multiply(help).mod(nGoth);

        G2 g2Zs=new G2();

        Fr zSFr=new Fr(zS.mod(n).toString(10),10);
        Mcl.mul(g2Zs,WeakBB.getG2(),zSFr);

        BigInteger eModed=eClientHash.mod(n);
        eModed=n.subtract(eModed);

        Fr eModedFr=new Fr(eModed.toString(),10);
        G2 helpPoint=new G2();
        Mcl.mul(helpPoint,clientPubKey,eModedFr);
        Mcl.add(g2Zs,g2Zs,helpPoint);

        BigInteger hashCheck=PaillierFunctions.hashCsClient(c1,c2,c3,g2Zs.serialize());

        if(hashCheck.equals(eClientHash))
            return true;
        else
            return false;
    }
    public void saveUserKeyToFile(G2 pubKeyUser,BigInteger userID){
        G2 invPubKey=new G2();
        Mcl.neg(invPubKey,pubKeyUser);
        activeManagerFile.addUserToManagerHashMap(userID,invPubKey);
        FileManagerClass.saveManagerKey(activeManagerFile);
    }

    public BigInteger myModPow(BigInteger num,BigInteger exponent,BigInteger modulus){
        if(useGMP==false) {
            BigInteger result = num.modPow(exponent, modulus);
            return result;
        }
        else{
            String resultString=modPowC(num.toString(10),exponent.toString(10),modulus.toString(10));
            return new BigInteger(resultString,10);
        }

    }
    public PaillierPublicKey getPaillierPublicKeyFromServer(){
        return kp.getPaillierPublicKey();
    }

    public G1 computePubManager(BigInteger e2){
        BigInteger x= PaillierFunctions.computeX(e2,kp.getPaillierPrivateKey(),n);
        BigInteger xInv= x.modInverse(n);
        Fr xFr=new Fr(xInv.toString(),10);
        pubManager= WeakBB.getG1();
        Mcl.mul(pubManager,pubManager,xFr);
        return pubManager;
    }
    public static boolean checkProof(SignatureProof sp, Fr msg,G2 groupPublicKey){
        //checking of pairing
        GT pair1 =new GT();
        G1 SiG=new G1();
        Mcl.add(SiG,sp.getSiDash(),sp.getGToR());

        Mcl.pairing(pair1,SiG,WeakBB.getG2());

        //G2 PK = new G2();
        //Mcl.mul(PK,WeakBB.getG2(),ManKey);
        GT pair2 = new GT();
        Mcl.pairing(pair2,sp.getSiAph(),groupPublicKey);


        if(!pair1.equals(pair2)){
            return false;
        }
        //end of pairing check
        //checking of t, later checking of hash
        G1 t2= new G1();
        G1 add1= new G1();
        Mcl.add(add1,sp.getSiDash(),sp.getGToR());
        Mcl.mul(add1,add1,sp.getE());
        //now we have Si*g' to e
        G1 SiToSSki= new G1();
        Mcl.mul(SiToSSki,sp.getSiAph(),sp.getSSki());
        G1 gToSr= new G1();
        Mcl.mul(gToSr,WeakBB.getG1(),sp.getSr());

        Mcl.add(t2,add1,SiToSSki);
        Mcl.add(t2,t2,gToSr);
        Fr e2= computeHashForCheck(sp.getGToR(),sp.getSiAph(),sp.getSiDash(),msg,t2);

        //Log.i("ProofCheck","t1= "+t.toString());
        //Log.i("ProofCheck","t2= "+t2.toString());
        //Log.i("ProofCheck"," are ts same? "+t.equals(t2));

        HashSet<byte[]> revoked=FileManagerClass.loadRevokedUsers(sp.groupID);
        Iterator<byte[]> iterator = revoked.iterator();
        while(iterator.hasNext()){
            byte[] invKey=iterator.next();
            G2 invKeyG2=new G2();
            invKeyG2.deserialize(invKey);
            int revokeResult= checkSignatureWithPK(invKeyG2,sp.getSiAph(),sp.getSiDash());
            if(revokeResult==0){
                System.out.println("This user is revoked");
                return false;
            }
        }

        if(sp.getE().equals(e2))
            return true;
        else
            return false;



    }
    public static Fr computeHashForCheck(G1 GtoR,G1 SiAph, G1 SiDash, Fr msg, G1 t2){
        MessageDigest hashing;
        try {
            hashing= MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write(GtoR.serialize());
            outputStream.write(SiAph.serialize());
            outputStream.write(SiDash.serialize());
            outputStream.write(t2.serialize());
            outputStream.write(msg.serialize());
            byte[] chained= outputStream.toByteArray();
            hashing.update(chained);
            byte [] hash= hashing.digest();
            BigInteger hashBig= new BigInteger(hash);
            hashBig= hashBig.mod(WeakBB.genNinBigInt());

            Fr hashFrCut=new Fr(hashBig.toString(10));
            return hashFrCut;

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    public static int checkSignatureWithPK(G2 PKiInv, G1 SiAph, G1 SiDash){
        GT pair1= new GT();
        GT pair2= new GT();
        Mcl.pairing(pair1,SiAph,PKiInv);
        Mcl.pairing(pair2,SiDash,WeakBB.getG2());
        if(pair1.equals(pair2)){
            //System.out.println("it is the user");
            return 0;
        }

        return -1;
    }
    public BigInteger openSignature(SignatureProof signatureProof){
        HashMap <BigInteger, byte[]> usersHashMap=activeManagerFile.getUserHashMap();
        if(!signatureProof.groupID.equals(managerID))
            return null;
        for(Map.Entry<BigInteger, byte[]> set :
                usersHashMap.entrySet()){
            G2 PKiInv=new G2();
            PKiInv.deserialize(set.getValue());
            if(checkSignatureWithPK(PKiInv,signatureProof.getSiAph(),signatureProof.getSiDash())==0){
                return set.getKey();
            }
        }
        return null;
    }
    public int revokeUser(BigInteger userID){
        HashMap<BigInteger, byte[]> allUsers=activeManagerFile.getUserHashMap();
        if(allUsers.containsKey(userID)){
            byte[] keyInvertedBytes=allUsers.get(userID);
            revokedUsers.add(keyInvertedBytes);
            //save the file
            return FileManagerClass.saveRevokedToFile(getManagerID(),revokedUsers);
        }
        else{
            return -1;
        }




    }

    public BigInteger getcGoth() {
        return cGoth;
    }

    public BigInteger getE1() {
        return e1;
    }

    public G2 getManagerPublicKey() {
        return managerPublicKey;
    }

    public FileOfManager getActiveManagerFile() {
        return activeManagerFile;
    }

    public BigInteger geteHash() {
        return eHash;
    }
    public native String modPowC(String a, String b, String mod);

    public BigInteger getManagerID() {
        return managerID;
    }

    public HashSet<byte[]> getRevokedUsers() {
        return revokedUsers;
    }
}
