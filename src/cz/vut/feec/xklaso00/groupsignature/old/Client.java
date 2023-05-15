package cz.vut.feec.xklaso00.groupsignature.old;


import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import com.herumi.mcl.Mcl;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.GroupSignatureFunctions;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.NIZKPKFunctions;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.PaillierPublicKey;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.SignatureProof;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Random;

public class Client {

    private BigInteger n;
    private BigInteger r1;
    private BigInteger r2;
    private BigInteger r3;
    private BigInteger clientPrivateECKey = new BigInteger("13337249686366074820472798437217270360184022881117993298216071563450838387625",10);
    private BigInteger TWO = new BigInteger("2");
    private BigInteger c2Goth;
    private G1 computedPrivateKey;

    private G1 pubUser;
    private Fr UserKey;
    private G2 publicKeyUser;
    private G1 SiAph;
    private G1 GtoR;
    private G1 SiDash;
    private Fr e;
    private Fr SSki;
    private Fr Sr;
    private G1 t;
    private BigInteger groupID=new BigInteger("53763a7a",16);

    private BigInteger eHashClient;


    private boolean useGMP=false;
    String TAG= "TimeStamps";
    public Client(){
        n=new BigInteger("2523648240000001BA344D8000000007FF9F800000000010A10000000000000D",16);
        UserKey= new Fr(clientPrivateECKey.toString(),10);
        publicKeyUser=new G2();
        Mcl.mul(publicKeyUser, GroupSignatureFunctions.getG2(),UserKey);
    }

    public Fr getRandomFr(){
        Fr fr= new Fr();
        BigInteger rand;
        do {
            rand = new BigInteger(254, new Random());
        }while (rand.compareTo(n)>= 0);
        fr.setStr(rand.toString(),10);
        //Log.i(TAG,"FR TO STRING "+fr.toString());
        return fr;
    }

    public BigInteger computeE2(BigInteger e1, PaillierPublicKey publicKey){
        BigInteger kquec= BigInteger.valueOf(2);
        kquec= kquec.pow(n.bitLength()*3);
        BigInteger bar= TWO.pow(4096);

        r1= NIZKPKFunctions.getRandom(n.bitLength(),n);
        r2= NIZKPKFunctions.getRandom(kquec.bitLength(),kquec);
        r3= NIZKPKFunctions.getRandom(bar.bitLength(),bar);
        BigInteger e2= NIZKPKFunctions.computeE2(r1,r2,r3,n,clientPrivateECKey,publicKey,e1);
        computeC2Goth(publicKey);
        return e2;
    }

    public BigInteger computeC2Goth(PaillierPublicKey publicKey) {
        c2Goth=publicKey.getGGoth().modPow(clientPrivateECKey,publicKey.getNGoth());
        BigInteger mid=publicKey.getHGoth().modPow(r3,publicKey.getNGoth());
        c2Goth=c2Goth.multiply(mid);
        c2Goth=c2Goth.mod(publicKey.getNGoth());

        return c2Goth;
    }

    public boolean checkIssuerZK(PaillierPublicKey pubK,BigInteger[] Zs,BigInteger e1,BigInteger c1Goth,BigInteger eHash){
        BigInteger z1=Zs[0];
        BigInteger z2=Zs[1];
        BigInteger z3=Zs[2];

        BigInteger nn=pubK.getNn();
        BigInteger nGoth=pubK.getNGoth();

        BigInteger hz1=myModPow(pubK.getH(),z1,nn);
        BigInteger gz2=myModPow(pubK.getG(),z2,nn);
        BigInteger frac=myModPow(pubK.getH(),pubK.getnHalf(),nn);
        frac=frac.modInverse(nn);
        frac=frac.multiply(e1);
        frac=frac.mod(nn);
        frac=myModPow(frac,eHash,nn);
        frac=frac.modInverse(nn);

        BigInteger t1Check=hz1.multiply(gz2);
        t1Check=t1Check.multiply(frac);
        t1Check=t1Check.mod(nn);
        //now we have t1'

        BigInteger gz1=myModPow(pubK.getGGoth(),z1,nGoth);
        BigInteger hz3=myModPow(pubK.getHGoth(),z3,nGoth);
        BigInteger ce=myModPow(c1Goth,eHash,nGoth);
        ce=ce.modInverse(nGoth);

        BigInteger t2Check=gz1.multiply(hz3);
        t2Check=t2Check.multiply(ce);
        t2Check=t2Check.mod(nGoth);

        BigInteger checkHash= NIZKPKFunctions.hashTs(t1Check,t2Check);

        //Log.i(TAG,"t1  "+t1Check.toString());
        //Log.i(TAG,"t2  "+t2Check.toString());
        if(checkHash.equals(eHash))
            return true;
        else
            return false;

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
    public G1 computeKeyFromManager(G1 pubManager){

        //now PubManager is sent to user...
        Fr r1Fr=new Fr(r1.toString(),10);
        pubUser=new G1();
        Mcl.mul(pubUser,pubManager,r1Fr);
        return pubUser;
    }


    public Fr createEHash(Fr msg){
        MessageDigest hashing;
        try {
            hashing= MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write(GtoR.serialize());
            outputStream.write(SiAph.serialize());
            outputStream.write(SiDash.serialize());
            outputStream.write(t.serialize());
            outputStream.write(msg.serialize());
            byte[] chained= outputStream.toByteArray();
            hashing.update(chained);
            byte [] hash= hashing.digest();
            BigInteger hashBig= new BigInteger(hash);
            hashBig= hashBig.mod(n);
            Fr hashFrCut=new Fr(hashBig.toString(10));
            return hashFrCut;

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    public BigInteger getR1() {
        return r1;
    }

    public void setR1(BigInteger r1) {
        this.r1 = r1;
    }

    public G1 getSiAph() {
        return SiAph;
    }

    public G1 getGtoR() {
        return GtoR;
    }

    public G1 getSiDash() {
        return SiDash;
    }

    public Fr getE() {
        return e;
    }

    public Fr getSSki() {
        return SSki;
    }

    public Fr getSr() {
        return Sr;
    }

    public G1 getT() {
        return t;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getC2Goth() {
        return c2Goth;
    }



    public BigInteger geteHashClient() {
        return eHashClient;
    }

    public G2 getPublicKeyUser() {
        return publicKeyUser;
    }

    public native String modPowC(String a, String b, String mod);
}
