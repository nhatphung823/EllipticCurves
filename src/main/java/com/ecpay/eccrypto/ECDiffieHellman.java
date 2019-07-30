package com.ecpay.eccrypto;

import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Created by Joe on July, 13 2018 .
 */
public class ECDiffieHellman {
  public static byte[] generateShareBytes(ECPrivateKeyParameters aKS, ECPublicKeyParameters bKP) {
    return bKP.getQ().multiply(aKS.getD()).getEncoded(false);
  }

  public static ECPoint generateSharePoint(ECPrivateKeyParameters aKS, ECPublicKeyParameters bKP) {
    return bKP.getQ().multiply(aKS.getD());
  }

  public static byte[] encryptWithAES(ECPrivateKeyParameters aKS, ECPublicKeyParameters bKP, byte[] rawData) {
    byte[] shareBytes = generateShareBytes(aKS, bKP);
    byte[] keyAES = new byte[32];
    System.arraycopy(shareBytes, shareBytes.length - 32, keyAES, 0, 32);

    return AES.encrypt(rawData, keyAES);
  }

  public static byte[] decryptWithAES(ECPrivateKeyParameters bKS, ECPublicKeyParameters aKP, byte[] encryptedData) {
    byte[] shareBytes = generateShareBytes(bKS, aKP);
    byte[] keyAES = new byte[32];
    System.arraycopy(shareBytes, shareBytes.length - 32, keyAES, 0, 32);

    return AES.decrypt(encryptedData, keyAES);
  }
}
