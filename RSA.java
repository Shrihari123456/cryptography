import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    private BigInteger p, q, n, phi, e, d;
    private static final SecureRandom random = new SecureRandom();

    public RSA(int bitLength) {
        generateKeys(bitLength);
    }

    private void generateKeys(int bitLength) {
        p = BigInteger.probablePrime(bitLength, random);
        q = BigInteger.probablePrime(bitLength, random);
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        e = BigInteger.valueOf(65537);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
            e = e.add(BigInteger.TWO);
        }

        d = e.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    public BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPow(d, n);
    }

    public BigInteger[] getPublicKey() {
        return new BigInteger[]{e, n};
    }

    public BigInteger[] getPrivateKey() {
        return new BigInteger[]{d, n};
    }
}
