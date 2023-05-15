package cz.vut.feec.xklaso00.groupsignature.cryptocore;

import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import com.herumi.mcl.Mcl;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class NIZKPKFunctions {
    private static boolean useGMP=false;
    //this function computes the E1 and ZK_man, returns the serialized object that can be sent, most of the times are commented now for less clutter
    public static ServerTwoPartyObject computeE1andZKManager(PaillierKeyPair kp,BigInteger serverPrivateECKey,BigInteger groupID){
        long startE=System.nanoTime();
        BigInteger r= getRandom(kp.getPaillierPrivateKey().getPhi().bitLength(),kp.getPaillierPrivateKey().getPhi());
        BigInteger e1= computeE1(kp.getPaillierPublicKey(),serverPrivateECKey,r);
        //System.out.println("E1 took" + (System.nanoTime()-startE)/1000000+" ms");

        //long start=System.nanoTime();
        BigInteger[] cGoth_rDash=computeCGoth(kp,serverPrivateECKey);
        //System.out.println("c1 took" + (System.nanoTime()-start)/1000000+" ms");
        BigInteger cGoth=cGoth_rDash[0];
        BigInteger r_dash=cGoth_rDash[1];
        //start=System.nanoTime();
        BigInteger[] ZkIssuerE=createZKIssuer(kp,serverPrivateECKey,r,r_dash);
        //System.out.println("ZK issuer took" + (System.nanoTime()-start)/1000000+" ms");
        BigInteger[] ZkIssuer= Arrays.copyOfRange(ZkIssuerE,0,ZkIssuerE.length-1);
        BigInteger eHash=ZkIssuerE[3];
        System.out.println("e1C1ZK took" + (System.nanoTime()-startE)/1000000+" ms");
        ServerTwoPartyObject par=new ServerTwoPartyObject(kp.getPaillierPublicKey(),e1,ZkIssuer,cGoth,eHash,groupID);
        return par;
    }
    //computation of CGoth
    public static BigInteger[] computeCGoth(PaillierKeyPair kp,BigInteger serverPrivateECKey){
        //I modified this to be NGoth not PhiNGoth
        BigInteger rDash= NIZKPKFunctions.getRandom(kp.getPaillierPublicKey().getNGoth().bitLength(),kp.getPaillierPublicKey().getNGoth());
        //changed to use C++
        //BigInteger cGoth=kp.getPaillierPublicKey().getGGoth().modPow(serverPrivateECKey,kp.getPaillierPublicKey().getNGoth());
        //BigInteger mid= kp.getPaillierPublicKey().getHGoth().modPow(rDash,kp.getPaillierPublicKey().getNGoth());
        BigInteger cGoth=myModPow(kp.getPaillierPublicKey().getGGoth(),serverPrivateECKey,kp.getPaillierPublicKey().getNGoth());
        BigInteger mid=myModPow(kp.getPaillierPublicKey().getHGoth(),rDash,kp.getPaillierPublicKey().getNGoth());
        cGoth=cGoth.multiply(mid);
        cGoth=cGoth.mod(kp.getPaillierPublicKey().getNGoth());
        BigInteger[] cGoth_rDash=new BigInteger[2];
        cGoth_rDash[0]=cGoth;
        cGoth_rDash[1]=rDash;
        return  cGoth_rDash;
    }
    //generate the ZKman, the parameters are Paillier parameters, serverPrivateKey, r and rDash used in the E1 comp
    public static BigInteger[] createZKIssuer(PaillierKeyPair kp, BigInteger serverPrivateECKey, BigInteger r,BigInteger rDash){
        PaillierPublicKey pubK=kp.getPaillierPublicKey();
        //PaillierPrivateKey privK=kp.getPaillierPrivateKey();

        BigInteger rho1= NIZKPKFunctions.getRandom(pubK.getNGoth().bitLength(),pubK.getNGoth());
        BigInteger rho2= NIZKPKFunctions.getRandom(pubK.getNn().bitLength(),pubK.getNn());
        BigInteger rho3= NIZKPKFunctions.getRandom(pubK.getNGoth().bitLength(),pubK.getNGoth());

        BigInteger t1=myModPow(pubK.getH(),rho1,pubK.getNn());
        BigInteger mid1=myModPow(pubK.getG(),rho2,pubK.getNn());
        t1=t1.multiply(mid1);
        t1=t1.mod(pubK.getNn());
        BigInteger t2=myModPow(pubK.getGGoth(),rho1,pubK.getNGoth());
        mid1=myModPow(pubK.getHGoth(),rho3,pubK.getNGoth());
        t2=t2.multiply(mid1);
        t2=t2.mod(pubK.getNGoth());
        BigInteger eHash=hashTs(t1,t2);

        //lets not mod since it wont do anything and it did not work in client
        BigInteger [] ZsAndEHash=new BigInteger[4];
        BigInteger z1= eHash.multiply(serverPrivateECKey);
        z1=z1.add(rho1);
        z1=z1.mod(pubK.getNGoth());

        BigInteger z2=eHash.multiply(r);
        z2=z2.add(rho2);
        z2=z2.mod(pubK.getNn());

        BigInteger z3=eHash.multiply(rDash);
        z3=z3.add(rho3);

        ZsAndEHash[0]=z1;
        ZsAndEHash[1]=z2;
        ZsAndEHash[2]=z3;
        ZsAndEHash[3]=eHash;

        return ZsAndEHash;
    }
    //hash function for manager NIZK
    public static BigInteger hashTs(BigInteger t1, BigInteger t2){
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
    //compute E1 for manager
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
    //function to check the user ZK, could probably change it to take the UserZKObject, oh well...
    public static boolean checkPKUser(BigInteger[] Zets,BigInteger e2,BigInteger c2Goth,BigInteger eClientHash, G2 clientPubKey,BigInteger e1,BigInteger n, PaillierKeyPair kp){

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
        Mcl.mul(g2Zs, GroupSignatureFunctions.getG2(),zSFr);

        BigInteger eModed=eClientHash.mod(n);
        eModed=n.subtract(eModed);

        Fr eModedFr=new Fr(eModed.toString(),10);
        G2 helpPoint=new G2();
        Mcl.mul(helpPoint,clientPubKey,eModedFr);
        Mcl.add(g2Zs,g2Zs,helpPoint);

        BigInteger hashCheck= NIZKPKFunctions.hashCsClient(c1,c2,c3,g2Zs.serialize());

        if(hashCheck.equals(eClientHash))
            return true;
        else
            return false;
    }
    //a function that deciphers e2 and computes the randomized G1 point, that the user must derandomize with r1
    public static G1 computeSigningKeyRandomized(BigInteger e2,PaillierKeyPair kp, BigInteger n){
        BigInteger x= computeX(e2,kp.getPaillierPrivateKey(),n);
        BigInteger xInv= x.modInverse(n);
        Fr xFr=new Fr(xInv.toString(),10);
        G1 pubManager= GroupSignatureFunctions.getG1();
        Mcl.mul(pubManager,pubManager,xFr);
        return pubManager;
    }

    //here is the client part of function

    public static boolean checkIssuerZK(PaillierPublicKey pubK,BigInteger[] Zs,BigInteger e1,BigInteger c1Goth,BigInteger eHash){
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

        if(checkHash.equals(eHash))
            return true;
        else
            return false;

    }
    //pass pre-generated r1 to this function (r1= NIZKPKFunctions.getRandom(n.bitLength(),n)) as it will be needed later, so save it somewhere
    public static UserZKObject computeE2AndUserZK(BigInteger r1,BigInteger n,BigInteger clientPrivateECKey,PaillierPublicKey publicKey,BigInteger e1,byte[] clientPubKey,BigInteger clientID){
        BigInteger kquec= BigInteger.valueOf(2);
        kquec= kquec.pow(n.bitLength()*3);
        BigInteger TWO = new BigInteger("2");
        BigInteger bar= TWO.pow(4096);


        BigInteger r2= NIZKPKFunctions.getRandom(kquec.bitLength(),kquec);
        BigInteger r3= NIZKPKFunctions.getRandom(bar.bitLength(),bar);
        BigInteger e2= NIZKPKFunctions.computeE2(r1,r2,r3,n,clientPrivateECKey,publicKey,e1);
        BigInteger c2Goth=computeC2Goth(publicKey,r3,clientPrivateECKey);
        BigInteger[] ZsAndEHash= computeUserZK(publicKey,e1,n,c2Goth,r1,r2,r3,clientPrivateECKey);
        BigInteger[] Zs= Arrays.copyOfRange(ZsAndEHash,0,ZsAndEHash.length-1);
        BigInteger eClientHash=ZsAndEHash[6];

        return new UserZKObject(Zs,e2,c2Goth,eClientHash,clientPubKey,clientID);
    }
    public static BigInteger computeC2Goth(PaillierPublicKey publicKey, BigInteger r3, BigInteger clientPrivateECKey) {
        BigInteger c2Goth=publicKey.getGGoth().modPow(clientPrivateECKey,publicKey.getNGoth());
        BigInteger mid=publicKey.getHGoth().modPow(r3,publicKey.getNGoth());
        c2Goth=c2Goth.multiply(mid);
        c2Goth=c2Goth.mod(publicKey.getNGoth());

        return c2Goth;
    }
    //returns Zs and E hash, could be modified to return the UserZKObject
    public static BigInteger [] computeUserZK(PaillierPublicKey pubK, BigInteger e1, BigInteger n,BigInteger c2Goth, BigInteger r1,BigInteger r2,BigInteger r3, BigInteger clientPrivateECKey){
        BigInteger nGoth=pubK.getNGoth();
        BigInteger nn= pubK.getNn();

        BigInteger rhoS= NIZKPKFunctions.getRandomFromGroup(n);
        BigInteger rhoGoth= NIZKPKFunctions.getRandomFromGroup(nGoth);
        BigInteger rhoAph= NIZKPKFunctions.getRandomFromGroup(nGoth);
        BigInteger rho1= NIZKPKFunctions.getRandomFromGroup(nGoth);
        BigInteger rho2= NIZKPKFunctions.getRandomFromGroup(nn);
        BigInteger rhoU= NIZKPKFunctions.getRandomFromGroup(nGoth);

        BigInteger alpha=myModPow(pubK.getH(),pubK.getnHalf(),nn);
        alpha=alpha.modInverse(nn);
        alpha=alpha.multiply(e1).mod(nn);
        BigInteger beta=myModPow(pubK.getH(),n,nn);

        //c1 comp
        BigInteger c1=myModPow(alpha,rho1,nn);
        BigInteger help=myModPow(pubK.getH(),rhoAph,nn);
        c1=c1.multiply(help);
        help=myModPow(beta,rho2,nn);
        c1=c1.multiply(help);
        help=myModPow(pubK.getG(),rhoGoth,nn);
        c1=c1.multiply(help).mod(nn);

        //c2 comp
        BigInteger c2=myModPow(pubK.getGGoth(),rhoS,nGoth);
        help=myModPow(pubK.getHGoth(),rhoGoth,nGoth);
        c2=c2.multiply(help).mod(nGoth);

        //c3 comp
        BigInteger c3=myModPow(c2Goth,rho1,nGoth);
        help=pubK.getGGoth().modInverse(nGoth);
        help=myModPow(help,rhoAph,nGoth);
        c3=c3.multiply(help);
        help=myModPow(pubK.getHGoth(),rhoU,nGoth);
        c3=c3.multiply(help).mod(nGoth);

        //c4 comp
        G2 c4=new G2();
        Fr rhoSFr=new Fr(rhoS.toString(),10);
        Mcl.mul(c4, GroupSignatureFunctions.getG2(),rhoSFr);

        //hash
        BigInteger eHashClient= NIZKPKFunctions.hashCsClient(c1,c2,c3,c4.serialize());

        BigInteger u=r3.negate();
        u=u.multiply(r1);

        BigInteger zS=eHashClient.multiply(clientPrivateECKey);
        zS=zS.add(rhoS);
        BigInteger z1=eHashClient.multiply(r1);
        z1=z1.add(rho1);
        BigInteger z2=eHashClient.multiply(r2);
        z2=z2.add(rho2);
        BigInteger zU=eHashClient.multiply(u);
        zU=zU.add(rhoU);
        BigInteger zGoth=eHashClient.multiply(r3);
        zGoth=zGoth.add(rhoGoth);

        BigInteger skiAph=clientPrivateECKey.multiply(r1);
        BigInteger zAph=eHashClient.multiply(skiAph).add(rhoAph);

        BigInteger [] ZetsAndEHash=new BigInteger[7];
        ZetsAndEHash[0]=zS;
        ZetsAndEHash[1]=z1;
        ZetsAndEHash[2]=z2;
        ZetsAndEHash[3]=zU;
        ZetsAndEHash[4]=zGoth;
        ZetsAndEHash[5]=zAph;
        ZetsAndEHash[6]=eHashClient;

        return ZetsAndEHash;
    }
    //function to compute the key by de-randomizing it, we run this in client class with save
    public static G1 computeKeyFromManager(G1 pubManager, BigInteger r1){

        //now PubManager is sent to user...
        Fr r1Fr=new Fr(r1.toString(),10);
        G1 signKey =new G1();
        Mcl.mul(signKey,pubManager,r1Fr);

        return signKey;
    }

    //function for check computation of ZKuser, to hash his values
    public static BigInteger hashCsClient(BigInteger c1, BigInteger c2,BigInteger c3, byte[] c4){
        try {
            /*System.out.println("c1 "+ Instructions.bytesToHex(c1.toByteArray()));
            System.out.println("c2 "+Instructions.bytesToHex(c2.toByteArray()));
            System.out.println("c3 "+Instructions.bytesToHex(c3.toByteArray()));
            System.out.println("c4 "+Instructions.bytesToHex(c4));*/
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
        BigInteger p;
        if(!useGMP)
            p= BigInteger.probablePrime(bitSize,rng);
        else {
            p=new BigInteger(bitSize,rng);
            String resFromC=prime(p.toString(10));
            p=new BigInteger(resFromC,10);

        }
        return p;
    }
    //function that can switch between GMP and BigInt
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
    public static int testGMP(){
        try {
            prime("210");
            System.out.println("GMP test performed successfully");
            return 0;
        }catch (Exception e){
            e.printStackTrace();
            System.out.println("GMP bindings do not work");
            return -1;
        }
    }

    public final static native String modPowC(String a, String b, String mod);
    public final static native String prime(String a);

    public static boolean isUseGMP() {
        return useGMP;
    }

    public static void setUseGMP(boolean useGMP) {
        NIZKPKFunctions.useGMP = useGMP;
    }
}
