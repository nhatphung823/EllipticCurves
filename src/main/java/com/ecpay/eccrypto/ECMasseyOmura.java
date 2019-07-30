package com.ecpay.eccrypto;

import org.bouncycastle.math.ec.ECPoint;
import java.math.BigInteger;

/**
 * Created by Joe on July, 05 2019 .
 * kInverse = k.modInverse(ec.getN())
 */
public class ECMasseyOmura {
  public static byte[][] encryptFirst(EllipticCurve ec, BigInteger key, byte[] rawData) {
    ECPoint point = ec.randomQ();
    byte[] keyAES = new byte[32];
    byte[] qArray = point.getEncoded(false);
    System.arraycopy(qArray, qArray.length - 32, keyAES, 0, 32);
    point = point.multiply(key);

    return new byte[][]{point.getEncoded(false), AES.encrypt(rawData, keyAES)};
  }

  public static byte[][] encryptSecond(EllipticCurve ec, BigInteger key, byte[][] blockEncrypted) {
    ECPoint point = ec.decodePoint(blockEncrypted[0]);
    point = point.multiply(key);

    return new byte[][]{point.getEncoded(false), blockEncrypted[1]};
  }

  public static byte[][] decryptFirst(EllipticCurve ec, BigInteger keyInverse, byte[][] blockEncrypted) {
    ECPoint point = ec.decodePoint(blockEncrypted[0]);
    point = point.multiply(keyInverse);

    return new byte[][]{point.getEncoded(false), blockEncrypted[1]};
  }

  public static byte[] decryptSecond(EllipticCurve ec, BigInteger keyInverse, byte[][] blockEncrypted) {
    ECPoint point = ec.decodePoint(blockEncrypted[0]);
    point = point.multiply(keyInverse);
    byte[] keyAES = new byte[32];
    byte[] qArray = point.getEncoded(false);
    System.arraycopy(qArray, qArray.length - 32, keyAES, 0, 32);

    return AES.decrypt(blockEncrypted[1], keyAES);
  }
}
