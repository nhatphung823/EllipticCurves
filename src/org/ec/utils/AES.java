package org.ec.utils;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Created by Joe on September, 01 2018 .
 */
public class AES {
  public static byte[] encrypt(byte[] rawData, byte[] key) {
    try {
      byte[] iv = new byte[16];
      System.arraycopy(key, key.length - 16, iv, 0, 16);
      return transform(key, iv, rawData, true);
    } catch (Exception e) {
      e.printStackTrace();
      return new byte[0];
    }
  }

  public static byte[] decrypt(byte[] encData, byte[] key) {
    try {
      byte[] iv = new byte[16];
      System.arraycopy(key, key.length - 16, iv, 0, 16);
      return transform(key, iv, encData, false);
    } catch (Exception e) {
      e.printStackTrace();
      return new byte[0];
    }
  }

  public static byte[] generateKey(String password, byte[] salt) {
    try {
      PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), salt, 50, 256);
      SecretKeyFactory keyFactory = SecretKeyFactory
          .getInstance("PBEWithSHA256And256BitAES-CBC-BC", new BouncyCastleProvider());
      SecretKeySpec secretKey =
          new SecretKeySpec(keyFactory.generateSecret(pbeKeySpec).getEncoded(), "AES");

      return secretKey.getEncoded();
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      return new byte[0];
    }
  }

  private static byte[] transform(byte[] key, byte[] iv, byte[] data, boolean encrypt)
      throws Exception {

    // setup cipher parameters with key and IV
    KeyParameter keyParam = new KeyParameter(key);
    CipherParameters params = new ParametersWithIV(keyParam, iv);

    // setup AES cipher in CBC mode with PKCS7 padding
    BlockCipherPadding padding = new PKCS7Padding();
    BufferedBlockCipher cipher =
        new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), padding);
    cipher.reset();
    cipher.init(encrypt, params);

    byte[] buf = new byte[cipher.getOutputSize(data.length)];
    int len = cipher.processBytes(data, 0, data.length, buf, 0);
    len += cipher.doFinal(buf, len);

    // remove padding
    byte[] out = new byte[len];
    System.arraycopy(buf, 0, out, 0, len);

    return out;
  }
}
