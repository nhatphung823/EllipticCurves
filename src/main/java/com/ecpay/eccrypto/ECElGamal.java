package com.ecpay.eccrypto;


import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

/**
 * Created by Joe on July, 13 2018 .
 */
public class ECElGamal {
  public static byte[][] encrypt(EllipticCurve ec, ECPublicKeyParameters kP, byte[] rawData){
    BigInteger n = ec.randomD();
    ECPoint ecPoint = ec.randomQ();
    ECPoint m1 = ec.getGPoint().multiply(n);
    ECPoint m2 = ecPoint.add(kP.getQ().multiply(n));
    byte[] keyAES = new byte[32];
    byte[] qArray = ecPoint.getEncoded(false);
    System.arraycopy(qArray, qArray.length - 32, keyAES, 0, 32);

    return  new byte[][]{m1.getEncoded(false), m2.getEncoded(false), AES.encrypt(rawData, keyAES)};
  }

  public static byte[] decrypt(EllipticCurve ec, ECPrivateKeyParameters kS, byte[][] blockEncrypted){
    ECPoint m1 = ec.decodePoint(blockEncrypted[0]);
    ECPoint m2 = ec.decodePoint(blockEncrypted[1]);
    ECPoint ecPoint = m2.subtract(m1.multiply(kS.getD()));
    byte[] keyAES = new byte[32];
    byte[] qArray = ecPoint.getEncoded(false);
    System.arraycopy(qArray, qArray.length - 32, keyAES, 0, 32);

    return AES.decrypt(blockEncrypted[2], keyAES);
  }
}
