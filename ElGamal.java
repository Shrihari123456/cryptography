import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class ElGamal {
    private BigInteger p, g, x, y;
    private Random rand = new Random();
    private static final SecureRandom random = new SecureRandom();

    public ElGamal(int bitLength) {
        generateKeys(bitLength);
    }

    private void generateKeys(int bitLength) {
        p = BigInteger.probablePrime(bitLength, random);
        g = BigInteger.valueOf(2);
        while (!isGenerator(g, p)) {
            g = g.add(BigInteger.ONE);
        }

        x = new BigInteger(bitLength - 1, rand);
        y = g.modPow(x, p);
    }

    private boolean isGenerator(BigInteger g, BigInteger p) {
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger factor = pMinusOne.divide(BigInteger.valueOf(2));
        return !g.modPow(factor, p).equals(BigInteger.ONE);
    }

    public BigInteger[] encrypt(BigInteger message) {
        BigInteger k = new BigInteger(p.bitLength() - 1, rand);
        BigInteger c1 = g.modPow(k, p);
        BigInteger c2 = message.multiply(y.modPow(k, p)).mod(p);
        return new BigInteger[]{c1, c2};
    }

    public BigInteger decrypt(BigInteger[] cipher) {
        BigInteger c1 = cipher[0];
        BigInteger c2 = cipher[1];
        BigInteger s = c1.modPow(x, p);
        return c2.multiply(s.modInverse(p)).mod(p);
    }
}
