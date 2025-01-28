import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class CryptographicAlgorithms {
    private static final SecureRandom random = new SecureRandom();

    // Affine Cipher Implementation
    public static class AffineCipher {
        public static String encrypt(String text, int a, int b) {
            if (gcd(a, 26) != 1) {
                throw new IllegalArgumentException("'a' must be coprime with 26");
            }

            StringBuilder result = new StringBuilder();
            text = text.toUpperCase();

            for (char c : text.toCharArray()) {
                if (Character.isLetter(c)) {
                    int x = c - 'A';
                    int encrypted = (a * x + b) % 26;
                    result.append((char) (encrypted + 'A'));
                } else {
                    result.append(c);
                }
            }
            return result.toString();
        }

        public static String decrypt(String text, int a, int b) {
            if (gcd(a, 26) != 1) {
                throw new IllegalArgumentException("'a' must be coprime with 26");
            }

            StringBuilder result = new StringBuilder();
            text = text.toUpperCase();
            int aInverse = modInverse(a, 26);

            for (char c : text.toCharArray()) {
                if (Character.isLetter(c)) {
                    int x = c - 'A';
                    int decrypted = (aInverse * (x - b + 26)) % 26;
                    result.append((char) (decrypted + 'A'));
                } else {
                    result.append(c);
                }
            }
            return result.toString();
        }
    }

    // Vigenere Cipher Implementation
    public static class VigenereCipher {
        public static String encrypt(String text, String key) {
            StringBuilder result = new StringBuilder();
            text = text.toUpperCase();
            key = key.toUpperCase();
            int keyLength = key.length();

            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (Character.isLetter(c)) {
                    int charValue = c - 'A';
                    int keyValue = key.charAt(i % keyLength) - 'A';
                    int encrypted = (charValue + keyValue) % 26;
                    result.append((char) (encrypted + 'A'));
                } else {
                    result.append(c);
                }
            }
            return result.toString();
        }

        public static String decrypt(String text, String key) {
            StringBuilder result = new StringBuilder();
            text = text.toUpperCase();
            key = key.toUpperCase();
            int keyLength = key.length();

            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (Character.isLetter(c)) {
                    int charValue = c - 'A';
                    int keyValue = key.charAt(i % keyLength) - 'A';
                    int decrypted = (charValue - keyValue + 26) % 26;
                    result.append((char) (decrypted + 'A'));
                } else {
                    result.append(c);
                }
            }
            return result.toString();
        }
    }

    // Extended Euclidean Algorithm Implementation
    public static class ExtendedEuclidean {
        static class Result {
            int gcd, x, y;
            Result(int gcd, int x, int y) {
                this.gcd = gcd;
                this.x = x;
                this.y = y;
            }
        }

        public static Result compute(int a, int b) {
            if (a == 0) {
                return new Result(b, 0, 1);
            }

            Result temp = compute(b % a, a);
            int x = temp.y - (b / a) * temp.x;
            int y = temp.x;

            return new Result(temp.gcd, x, y);
        }
    }

    // RSA Implementation
    public static class RSA {
        private BigInteger p, q, n, phi, e, d;

        public RSA(int bitLength) {
            generateKeys(bitLength);
        }

        private void generateKeys(int bitLength) {
            // Generate two prime numbers
            p = BigInteger.probablePrime(bitLength, random);
            q = BigInteger.probablePrime(bitLength, random);

            // Calculate n and phi
            n = p.multiply(q);
            phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            // Choose e
            e = BigInteger.valueOf(65537); // Common value for e
            while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0) {
                e = e.add(BigInteger.TWO);
            }

            // Calculate d
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

    // ElGamal Implementation
    public static class ElGamal {
        private BigInteger p, g, x, y;
        private Random rand = new Random();

        public ElGamal(int bitLength) {
            generateKeys(bitLength);
        }

        private void generateKeys(int bitLength) {
            // Generate prime p
            p = BigInteger.probablePrime(bitLength, random);
            
            // Find generator g
            g = BigInteger.valueOf(2);
            while (!isGenerator(g, p)) {
                g = g.add(BigInteger.ONE);
            }

            // Generate private key x
            x = new BigInteger(bitLength - 1, rand);
            
            // Calculate public key y = g^x mod p
            y = g.modPow(x, p);
        }

        private boolean isGenerator(BigInteger g, BigInteger p) {
            BigInteger pMinusOne = p.subtract(BigInteger.ONE);
            BigInteger factor = pMinusOne.divide(BigInteger.valueOf(2));
            return !g.modPow(factor, p).equals(BigInteger.ONE);
        }

        public BigInteger[] encrypt(BigInteger message) {
            // Generate random k
            BigInteger k = new BigInteger(p.bitLength() - 1, rand);
            
            // Calculate c1 = g^k mod p
            BigInteger c1 = g.modPow(k, p);
            
            // Calculate c2 = m * y^k mod p
            BigInteger c2 = message.multiply(y.modPow(k, p)).mod(p);
            
            return new BigInteger[]{c1, c2};
        }

        public BigInteger decrypt(BigInteger[] cipher) {
            BigInteger c1 = cipher[0];
            BigInteger c2 = cipher[1];
            
            // Calculate s = c1^x mod p
            BigInteger s = c1.modPow(x, p);
            
            // Calculate m = c2 * s^(-1) mod p
            return c2.multiply(s.modInverse(p)).mod(p);
        }
    }

    // Utility methods
    private static int gcd(int a, int b) {
        if (b == 0) return a;
        return gcd(b, a % b);
    }

    private static int modInverse(int a, int m) {
        ExtendedEuclidean.Result result = ExtendedEuclidean.compute(a, m);
        int x = result.x;
        return (x % m + m) % m;
    }

    public static void main(String[] args) {
        // Test Affine Cipher
        System.out.println("Affine Cipher Test:");
        String text = "HELLO";
        int a = 5, b = 8;
        String encrypted = AffineCipher.encrypt(text, a, b);
        String decrypted = AffineCipher.decrypt(encrypted, a, b);
        System.out.println("Original: " + text);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        // Test Vigenere Cipher
        System.out.println("\nVigenere Cipher Test:");
        String key = "KEY";
        encrypted = VigenereCipher.encrypt(text, key);
        decrypted = VigenereCipher.decrypt(encrypted, key);
        System.out.println("Original: " + text);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);

        // Test RSA
        System.out.println("\nRSA Test:");
        RSA rsa = new RSA(512);
        BigInteger message = new BigInteger("123");
        BigInteger encryptedMsg = rsa.encrypt(message);
        BigInteger decryptedMsg = rsa.decrypt(encryptedMsg);
        System.out.println("Original: " + message);
        System.out.println("Encrypted: " + encryptedMsg);
        System.out.println("Decrypted: " + decryptedMsg);

        // Test ElGamal
        System.out.println("\nElGamal Test:");
        ElGamal elGamal = new ElGamal(64);
        BigInteger msg = new BigInteger("123");
        BigInteger[] encryptedElGamal = elGamal.encrypt(msg);
        BigInteger decryptedElGamal = elGamal.decrypt(encryptedElGamal);
        System.out.println("Original: " + msg);
        System.out.println("Encrypted: (c1=" + encryptedElGamal[0] + ", c2=" + encryptedElGamal[1] + ")");
        System.out.println("Decrypted: " + decryptedElGamal);
    }
}