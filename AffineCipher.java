public class AffineCipher {
    public static void main(String[] args) {
        System.out.println("Affine Cipher Test:");
        String text = "HELLO";
        int a = 5, b = 8;

        String encrypted = encrypt(text, a, b);
        String decrypted = decrypt(encrypted, a, b);

        System.out.println("Original: " + text);
        System.out.println("Encrypted: " + encrypted);
        System.out.println("Decrypted: " + decrypted);
    }

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

    private static int gcd(int a, int b) {
        if (b == 0) return a;
        return gcd(b, a % b);
    }

    private static int modInverse(int a, int m) {
        Result result = computeExtendedGCD(a, m);
        int x = result.x;
        return (x % m + m) % m;
    }

    static class Result {
        int gcd, x, y;
        Result(int gcd, int x, int y) {
            this.gcd = gcd;
            this.x = x;
            this.y = y;
        }
    }

    public static Result computeExtendedGCD(int a, int b) {
        if (a == 0) {
            return new Result(b, 0, 1);
        }

        Result temp = computeExtendedGCD(b % a, a);
        int x = temp.y - (b / a) * temp.x;
        int y = temp.x;

        return new Result(temp.gcd, x, y);
    }
}
