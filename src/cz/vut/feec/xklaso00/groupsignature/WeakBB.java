package cz.vut.feec.xklaso00.groupsignature;

import com.herumi.mcl.Fp;
import com.herumi.mcl.Fr;
import com.herumi.mcl.G1;
import com.herumi.mcl.G2;
import com.herumi.mcl.GT;
import com.herumi.mcl.Mcl;

import java.math.BigInteger;

public class WeakBB {
    public static String TAG= "WeakBBClass";

    /*public static PrivateKey generatePrivateKey(){
        PrivateKey pk= new PrivateKey();
        Log.i(TAG,pk.toString());
        return pk;
    }*/

    private static G2 getG2(){
        /*Fp fp1= new Fp("12723517038133731887338407189719511622662176727675373276651903807414909099441",10);
        Fp fp2=new Fp("4168783608814932154536427934509895782246573715297911553964171371032945126671",10);
        Fp fp3= new Fp("13891744915211034074451795021214165905772212241412891944830863846330766296736",10);
        Fp fp4= new Fp("7937318970632701341203597196594272556916396164729705624521405069090520231616",10);*/
        Fp fp1= new Fp("061a10bb519eb62feb8d8c7e8c61edb6a4648bbb4898bf0d91ee4224c803fb2b",16);
        Fp fp2=new Fp("0516aaf9ba737833310aa78c5982aa5b1f4d746bae3784b70d8c34c1e7d54cf3",16);
        Fp fp3= new Fp("021897a06baf93439a90e096698c822329bd0ae6bdbe09bd19f0e07891cd2b9a",16);
        Fp fp4= new Fp("0ebb2b0e7c8b15268f6d4456f5f38d37b09006ffd739c9578a2d1aec6b3ace9b",16);
        G2 gen2= new G2(fp1,fp2,fp3,fp4);
        return gen2;
    }

    private static  G1 getG1(){
        Fp fr1= new Fp("2523648240000001BA344D80000000086121000000000013A700000000000012",16);
        Fp fr2=new Fp("1",16);
        G1 generator= new G1(fr1,fr2);
        return generator;
    }
    public static G1 signWbb(Fr sk, Fr msg){
        Fr exponent= new Fr();
        Mcl.add(exponent,sk,msg);
        //Mcl.inv(exponent,exponent);
        //Log.i("MainAct","Exponent "+exponent.toString());
        BigInteger bigg= new BigInteger(exponent.toString(),10);


        bigg=bigg.modInverse(new BigInteger("2523648240000001BA344D8000000007FF9F800000000010A10000000000000D",16));

        exponent.setStr(bigg.toString(),10);

        G1 sign= getG1();
        Mcl.mul(sign,sign,exponent);
        return sign;
    }

    public static boolean verify(G2 pk,G1 sign,Fr msg){

        G2 p=pk;
        G2 temp= getG2();
        Mcl.mul(temp,temp,msg);
        Mcl.add(p,p,temp);

        GT result= new GT();
        Mcl.pairing(result,sign,p);

        GT comp= new GT();
        Mcl.pairing(comp,getG1(),getG2());


        return comp.equals(result);

    }
    public static BigInteger genNinBigInt()
    {
        return new BigInteger("2523648240000001BA344D8000000007FF9F800000000010A10000000000000D",16);
    }
}
