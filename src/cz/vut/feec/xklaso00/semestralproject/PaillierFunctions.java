package cz.vut.feec.xklaso00.semestralproject;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;

public class PaillierFunctions {
    private static boolean useGMP=false;
    public static BigInteger encrypt(BigInteger m,PaillierPublicKey publicKey){
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

    public static BigInteger getRandom (int length, BigInteger n){
        Random rng= new Random();
        BigInteger r;
        do{
            r=new BigInteger(length,rng);
        }while(r.compareTo(n)>=0);
        return r;
    }
    public static BigInteger getRandomFromGroup ( BigInteger n){
        Random rng= new Random();
        BigInteger r;
        do{
            r=new BigInteger(n.bitLength(),rng);
        }while(r.compareTo(n)>=0);
        return r;
    }

    public static BigInteger computeE1(PaillierPublicKey publicKey, BigInteger sk, BigInteger r){
        BigInteger e;

        BigDecimal bd= new BigDecimal(publicKey.getN());
        bd= bd.divide(new BigDecimal(2), RoundingMode.FLOOR);

        BigInteger nHalf= bd.toBigInteger();

        BigInteger exponent= nHalf;
        exponent=exponent.add(sk);
        //e=publicKey.getH().modPow(exponent,publicKey.getNn());
        e=myModPow(publicKey.getH(),exponent,publicKey.getNn());

        //BigInteger gr= publicKey.getG().modPow(r,publicKey.getNn());
        BigInteger gr= myModPow(publicKey.getG(),r,publicKey.getNn());
        e= e.multiply(gr);
        e=e.mod(publicKey.getNn());
        return e;
    }

    public static BigInteger hashTsServer(BigInteger t1, BigInteger t2){
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

    public static BigInteger hashCsClient(BigInteger c1, BigInteger c2,BigInteger c3, byte[] c4){
        try {
            MessageDigest hashing = MessageDigest.getInstance("SHA-256");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
            outputStream.write(c1.toByteArray());
            outputStream.write(c2.toByteArray());
            outputStream.write(c3.toByteArray());
            outputStream.write(c4);
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

    public static BigInteger computeE2(BigInteger r1, BigInteger r2, BigInteger r3, BigInteger qec, BigInteger sk, PaillierPublicKey publicKey, BigInteger e1){
        BigInteger e2;
        e2=e1;
        BigInteger n= publicKey.getN();
        BigInteger h= publicKey.getH();
        BigDecimal bd= new BigDecimal(publicKey.getN());
        bd= bd.divide(new BigDecimal(2), RoundingMode.FLOOR);

        BigInteger nHalf= bd.toBigInteger();

        //e2= e1.divide(publicKey.getH().divide(BigInteger.TWO));
        //BigInteger hton2= h.modPow(nHalf,publicKey.getNn());
        BigInteger hton2=myModPow(h,nHalf,publicKey.getNn());
        hton2=hton2.modInverse(publicKey.getNn());
        e2=e1.multiply(hton2);
        //e2=e1.divide(hton2);

        e2= e2.modPow(r1,publicKey.getNn());


        BigInteger exponent=nHalf;
        BigInteger skr1= sk.multiply(r1);
        BigInteger r2qec= r2.multiply(qec);
        exponent=exponent.add(skr1);
        exponent=exponent.add(r2qec);
        //BigInteger hToExp= h.modPow(exponent,publicKey.getNn());
        BigInteger hToExp=myModPow(h,exponent,publicKey.getNn());
        //BigInteger gToR3=publicKey.getG().modPow(r3,publicKey.getNn());
        BigInteger gToR3=myModPow(publicKey.getG(),r3,publicKey.getNn());

        e2=e2.multiply(hToExp);
        e2=e2.mod(publicKey.getNn());
        e2= e2.multiply(gToR3);
        e2= e2.mod(publicKey.getNn());


        return e2;
    }
    public static BigInteger afterDecrypt(BigInteger msg, BigInteger qec, BigInteger n){
        BigInteger toReturn= msg.subtract(n.divide(new BigInteger("2")));
        toReturn=toReturn.mod(n);
        toReturn=toReturn.mod(qec);


        return toReturn;
    }
    public static BigInteger computeX(BigInteger e2, PaillierPrivateKey privateKey, BigInteger qec){
        BigInteger dec;
        //dec=e2.modPow(privateKey.getPhi(),privateKey.getNn());
        dec=myModPow(e2,privateKey.getPhi(),privateKey.getNn());

        dec=dec.subtract(BigInteger.ONE);
        dec=dec.divide(privateKey.getN());
        dec=dec.mod(privateKey.getNn());

        BigInteger phiInv= privateKey.getPhi().modInverse(privateKey.getN());
        dec=dec.multiply(phiInv);
        dec=dec.mod(privateKey.getN());


        BigDecimal bd= new BigDecimal(privateKey.getN());
        bd= bd.divide(new BigDecimal( 2), RoundingMode.FLOOR);

        BigInteger nHalf= bd.toBigInteger();



        dec=dec.subtract(nHalf);
        dec=dec.mod(privateKey.getN());
        dec=dec.mod(qec);


        return dec;
    }
    public static BigInteger generateRandomPrime(int bitSize){
        Random rng= new SecureRandom();
        BigInteger p= BigInteger.probablePrime(bitSize,rng);
        return p;
    }
    public static BigInteger myModPow(BigInteger num,BigInteger exponent,BigInteger modulus){
        if(useGMP==false) {
            BigInteger result = num.modPow(exponent, modulus);
            return result;
        }
        else{
            String resultString=modPowC(num.toString(10),exponent.toString(10),modulus.toString(10));
            return new BigInteger(resultString,10);
        }


    }

    public static native String modPowC(String a, String b, String mod);
}
