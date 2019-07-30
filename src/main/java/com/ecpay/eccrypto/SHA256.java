package com.ecpay.eccrypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Joe on July, 30 2019 .
 */
public class SHA256 {
  public static byte[] hash(byte[] destination) {
    MessageDigest digest = null;
    try {
      digest = MessageDigest.getInstance("SHA-256");
      return digest.digest(destination);
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      return new byte[32];
    }
  }
}
