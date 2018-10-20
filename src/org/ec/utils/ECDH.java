package org.ec.utils;


import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.util.encoders.Base64;

/**
 * Created by Joe on July, 13 2018 .
 */
public class ECDH {
  public static byte[] generateShareSecret(ECPrivateKeyParameters ksParams, ECPublicKeyParameters kpParams) {
    ECDHBasicAgreement agreement = new ECDHBasicAgreement();
    agreement.init(ksParams);
    byte[] shareSecret = agreement.calculateAgreement(kpParams).toByteArray();

    return AES.generateKey(Base64.toBase64String(shareSecret), shareSecret);
  }

  public static void main(String[] args) {
    EllipticCurve ec = EllipticCurve.getSecp256k1();
    ECPrivateKeyParameters aKS = ec.generatePrivateKeyParameters();
    System.out.println("aKS : " + aKS.getD());
    System.out.println(new String(Base64.encode(aKS.getD().toByteArray())));
    ECPublicKeyParameters aKP = ec.getPublicKeyParameters(aKS);
    System.out.println("aKP : " + new String(Base64.encode(aKP.getQ().getEncoded(false))));

    ECPrivateKeyParameters bKS = ec.generatePrivateKeyParameters();
    System.out.println("bKS : " + bKS.getD());
    ECPublicKeyParameters bKP = ec.getPublicKeyParameters(bKS);
    System.out.println("bKP : " + new String(Base64.encode(bKP.getQ().getEncoded(false))));

    byte[] aShareSecret = generateShareSecret(aKS, bKP);
    byte[] bShareSecret = generateShareSecret(bKS, aKP);

    String data = "Khong co gi quy hon doc lap tu do";

    byte[] encData = AES.encrypt(data.getBytes(), aShareSecret);
    System.out.println(new String(Base64.encode(encData)));
    byte[] decData = AES.decrypt(encData, bShareSecret);
    System.out.println(new String(decData));
  }
}
