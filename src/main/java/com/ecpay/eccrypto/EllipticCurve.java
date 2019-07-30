package com.ecpay.eccrypto;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Created by Joe on July, 13 2018 .
 */
public class EllipticCurve {
  //prime field
  private BigInteger p;
  //a factor
  private BigInteger a;
  //b factor
  private BigInteger b;
  // G base point
  private BigInteger g;
  //N order of G
  private BigInteger n;

  private ECCurve.Fp curve;
  private ECDomainParameters ecDomain;

  public EllipticCurve(BigInteger p, BigInteger a, BigInteger b, BigInteger g, BigInteger n) {
    this.p = p;
    this.a = a;
    this.b = b;
    this.g = g;
    this.n = n;
    curve = new ECCurve.Fp(p, a, b, n, ECConstants.ONE);
    ecDomain = new ECDomainParameters(curve, curve.decodePoint(g.toByteArray()), n);
  }

  private EllipticCurve() {
  }

  public AsymmetricCipherKeyPair generateKeyPair() {
    ECKeyPairGenerator pGen = new ECKeyPairGenerator();
    ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(ecDomain, secureRandom);
    pGen.init(genParam);

    return pGen.generateKeyPair();
  }

  public ECPrivateKeyParameters generatePrivateKeyParameters(BigInteger secret) {
    return new ECPrivateKeyParameters(secret, ecDomain);
  }

  public ECPrivateKeyParameters generatePrivateKeyParameters() {
    return (ECPrivateKeyParameters) generateKeyPair().getPrivate();
  }

  public ECPublicKeyParameters getPublicKeyParameters(BigInteger secret) {
    ECPoint ecPoint = ecDomain.getG().multiply(secret);
    return new ECPublicKeyParameters(ecPoint, ecDomain);
  }

  public ECPublicKeyParameters getPublicKeyParameters(ECPrivateKeyParameters privateKeyParameters) {
    ECPoint ecPoint = ecDomain.getG().multiply(privateKeyParameters.getD());
    return new ECPublicKeyParameters(ecPoint, ecDomain);
  }

  public ECPublicKeyParameters getPublicKeyParameters(byte[] Q) {
    return new ECPublicKeyParameters(decodePoint(Q), ecDomain);
  }

  public byte[] sign(ECPrivateKeyParameters privateKeyParameters, byte[] dataSign) throws IOException {
    ECDSASigner signer = new ECDSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    signer.init(true, privateKeyParameters);
    BigInteger[] signature = signer.generateSignature(dataSign);
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DERSequenceGenerator seq = new DERSequenceGenerator(baos);
    BigInteger HALF_CURVE_ORDER = ecDomain.getN().shiftRight(1);
    seq.addObject(new ASN1Integer(signature[0]));
    seq.addObject(new ASN1Integer(
        signature[1].compareTo(HALF_CURVE_ORDER) <= 0 ? signature[1] : ecDomain.getN().subtract(signature[1])
    ));
    seq.close();
    return baos.toByteArray();
  }

  public boolean verify(byte[] dataSign, byte[] signature, ECPublicKeyParameters publicKeyParameters) {
    ASN1InputStream asn1 = new ASN1InputStream(signature);
    try {
      ECDSASigner signer = new ECDSASigner();
      signer.init(false, publicKeyParameters);
      DLSequence seq = (DLSequence) asn1.readObject();
      BigInteger r = ((ASN1Integer) seq.getObjectAt(0)).getPositiveValue();
      BigInteger s = ((ASN1Integer) seq.getObjectAt(1)).getPositiveValue();
      return signer.verifySignature(dataSign, r, s);
    } catch (Exception e) {
      e.printStackTrace();
      return false;
    } finally {
      try {
        asn1.close();
      } catch (IOException ignored) {
      }
    }
  }

  public ECPoint decodePoint(byte[] var) {
    return curve.decodePoint(var);
  }

  static SecureRandom secureRandom;

  static {
    try {
      secureRandom = SecureRandom.getInstance("SHA1PRNG");
    } catch (NoSuchAlgorithmException e) {
      secureRandom = new SecureRandom();
    }
  }

  public BigInteger getP() {
    return p;
  }

  public BigInteger getA() {
    return a;
  }

  public BigInteger getB() {
    return b;
  }

  public BigInteger getG() {
    return g;
  }

  public BigInteger getN() {
    return n;
  }

  public ECCurve.Fp getCurve() {
    return curve;
  }

  public ECDomainParameters getECDomain() {
    return ecDomain;
  }

  public BigInteger randomD() {
    int nBitLength = ecDomain.getN().bitLength();
    BigInteger k = new BigInteger(nBitLength, secureRandom);

    while (k.equals(ECConstants.ZERO) || (k.compareTo(ecDomain.getN()) >= 0)) {
      k = new BigInteger(nBitLength, secureRandom);
    }

    return k;
  }

  public ECPoint encodeToECPoint(byte[] message) {
    int lBits = n.bitLength() / 2;
    if (message.length * 8 > lBits) {
      throw new IllegalArgumentException("Message too large to be encoded(more than " + lBits / 8 + " bytes)");
    }

    BigInteger mask = BigInteger.ZERO.flipBit(lBits).subtract(BigInteger.ONE);
    BigInteger m = new BigInteger(1, message);
    ECFieldElement a = ecDomain.getCurve().getA();
    ECFieldElement b = ecDomain.getCurve().getB();

    BigInteger r;
    ECFieldElement x = null, y = null;
    do {
      r = randomD();
      r = r.andNot(mask).or(m);
      if (!ecDomain.getCurve().isValidFieldElement(r)) {
        continue;
      }
      x = ecDomain.getCurve().fromBigInteger(r);

      // y^2 = x^3 + ax + b = (x^2+a)x +b
      ECFieldElement y2 = x.square().add(a).multiply(x).add(b);
      y = y2.sqrt();
    } while (y == null);

    return ecDomain.getCurve().createPoint(x.toBigInteger(), y.toBigInteger());
  }

  public byte[] decodeFromECPoint(ECPoint point) {
    int lBits = n.bitLength() / 2;
    byte[] bs = new byte[lBits / 8];
    byte[] xbytes = point.normalize().getAffineXCoord().toBigInteger().toByteArray();
    System.arraycopy(xbytes, xbytes.length - bs.length, bs, 0, bs.length);
    return bs;
  }

  public ECPoint randomQ(){
    return ecDomain.getG().multiply(randomD());
  }

  public ECPoint getGPoint(){
    return ecDomain.getG();
  }

  public static EllipticCurve getSecp256k1(){
    return new EllipticCurve(
        new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
        new BigInteger("0000000000000000000000000000000000000000000000000000000000000000", 16),
        new BigInteger("0000000000000000000000000000000000000000000000000000000000000007", 16),
        new BigInteger("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
        new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
    );
  }
}
