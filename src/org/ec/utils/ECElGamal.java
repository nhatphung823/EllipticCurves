package org.ec.utils;


import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by Joe on July, 13 2018 .
 */
public class ECElGamal {
  public static byte[] encrypt(EllipticCurve ec, byte[] rawData, ECPrivateKeyParameters aKS, ECPublicKeyParameters bKP) {
    int blockSize = ec.getN().bitLength() / 16;
    List<byte[]> srcList = getBytesBlockSize(rawData, blockSize);
    int length = 0;
    List<byte[]> destList = new ArrayList<>();
    for (byte[] src : srcList) {
      ECPoint mPoint = ec.encodeToECPoint(src);
      ECPoint _mPoint = mPoint.add(bKP.getQ().multiply(aKS.getD()));
      byte[] bytesEnc = _mPoint.getEncoded(false);
      destList.add(bytesEnc);
      length += bytesEnc.length;
    }

    return toBytesArray(destList, length);

    /*ECPoint mPoint = ec.encodeToECPoint(rawData);
    ECPoint _mPoint = mPoint.add(bKP.getP().multiply(aKS.getD()));
    return _mPoint.getEncoded(false);*/
  }

  public static byte[] decrypt(EllipticCurve ec, byte[] encData, ECPrivateKeyParameters bKS, ECPublicKeyParameters aKP) {
    List<byte[]> srcList = getBytesBlockSize(encData, 61);
    List<byte[]> destList = new ArrayList<>();
    int length = 0;
    for (byte[] src : srcList) {
      ECPoint _mPoint = ec.decodePoint(src);
      ECPoint mPoint = _mPoint.subtract(aKP.getQ().multiply(bKS.getD()));
      byte[] bytesDec = ec.decodeFromECPoint(mPoint);
      destList.add(bytesDec);
      length += bytesDec.length;
    }

    return toBytesArray(destList, length);

    /*ECPoint _mPoint = ec.decodePoint(encData);
    ECPoint mPoint = _mPoint.subtract(aKP.getP().multiply(bKS.getD()));
    return ec.decodeFromECPoint(mPoint);*/
  }

  private static List<byte[]> getBytesBlockSize(byte[] src, int blockSize) {
    List<byte[]> list = new ArrayList<>();
    int a = src.length / blockSize;
    int m = src.length % blockSize;
    if (a > 0) {
      for (int i = 0; i < a; i++) {
        byte[] b = new byte[blockSize];
        System.arraycopy(src, i * blockSize, b, 0, blockSize);
        list.add(b);
      }
      if (m > 0) {
        byte[] b = new byte[m];
        System.arraycopy(src, a * blockSize, b, 0, m);
        list.add(b);
      }
    } else {
      list.add(src);
    }
    return list;
  }

  private static byte[] toBytesArray(List<byte[]> list, int length) {
    int blockSize = 0;
    byte[] bytes = new byte[length];
    for (int i = 0; i < list.size(); i++) {
      System.arraycopy(list.get(i), 0, bytes, blockSize, list.get(i).length);
      blockSize += list.get(i).length;
    }
    return bytes;
  }

  private static byte[] randomBytes (int length){
    SecureRandom random;
    try{
      random = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      random = new SecureRandom();
    }
    byte[] randomBytes = new byte[length];
    random.nextBytes(randomBytes);

    return randomBytes;
  }

  public static void main(String[] args) throws IOException {
    EllipticCurve ellipticCurve = new EllipticCurve(
        new BigInteger("883423532389192164791648750360308885314476597252960362792450860609699839"),
        new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
        new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16),
        new BigInteger("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf", 16),
        new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307")
    );

    String s = "012345678901234567890123";
    System.out.println(s);
    ECPrivateKeyParameters aKS = ellipticCurve.generatePrivateKeyParameters();
    ECPublicKeyParameters aKP = ellipticCurve.getPublicKeyParameters(aKS);

    ECPrivateKeyParameters bKS = ellipticCurve.generatePrivateKeyParameters();
    ECPublicKeyParameters bKP = ellipticCurve.getPublicKeyParameters(bKS);

    byte[] encData = ECElGamal.encrypt(ellipticCurve, s.getBytes(), aKS, bKP);
    System.out.println(new String(Base64.encode(encData)));

    byte[] rawData = ECElGamal.decrypt(ellipticCurve, encData, bKS, aKP);
    System.out.println(new String(rawData));
  }
}
