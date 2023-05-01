package cz.vut.feec.xklaso00.groupsignature.old;

import cz.vut.feec.xklaso00.groupsignature.cryptocore.PaillierPrivateKey;
import cz.vut.feec.xklaso00.groupsignature.cryptocore.PaillierPublicKey;

import java.math.BigInteger;
import java.util.Random;

public class OldFunctions {
    public static BigInteger encrypt(BigInteger m, PaillierPublicKey publicKey){
        Random rng= new Random();
        BigInteger nn= publicKey.getNn();
        BigInteger n= publicKey.getN();
        BigInteger r;
        do{
            r=new BigInteger(publicKey.getBitSize(),rng);
        }
        while(r.compareTo(publicKey.getN())>=0);
        BigInteger gm= publicKey.getG().modPow(m,nn);
        BigInteger rn= r.modPow(n,nn);
        BigInteger c= gm.multiply(rn);
        c=c.mod(nn);



        return c;
    }

    public static BigInteger decrypt(BigInteger c, PaillierPrivateKey privateKey){
        BigInteger m;

        BigInteger L=c.modPow(privateKey.getLambda(),privateKey.getNn());
        L=L.subtract(BigInteger.ONE).divide(privateKey.getN());

        m= L.multiply(privateKey.getMu());
        //BigInteger inv= privateKey.getLambda().modInverse(privateKey.getN());
        //m=L.multiply(inv);

        m=m.mod(privateKey.getN());


        return m;
    }
    public static BigInteger afterDecrypt(BigInteger msg, BigInteger qec, BigInteger n){
        BigInteger toReturn= msg.subtract(n.divide(new BigInteger("2")));
        toReturn=toReturn.mod(n);
        toReturn=toReturn.mod(qec);


        return toReturn;
    }
}
