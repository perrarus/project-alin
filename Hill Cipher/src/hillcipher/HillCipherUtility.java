/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */

package hillcipher;

import java.util.ArrayList;
import java.util.List;

public class HillCipherUtility {
    
    // konversi huruf ke angka (a = 0, b = 1, ..., z = 25)
    public static int letterToNumber(char letter) {
        return Character.toLowerCase(letter) - 'a';  // a = 0
    }
    
    // konversi angka ke huruf (0 = A, 1 = B, ..., 25 = Z)
    public static String numberToLetter(int number) {
        int adjustedNumber = number % 26;
        if (adjustedNumber < 0) adjustedNumber += 26;
        return String.valueOf((char) (adjustedNumber + 'A'));
    }
    
    // konversi karakter ke angka 
    public static int charToNumber(char ch) {
        if (Character.isLetter(ch)) {
            // huruf: A=0, ..., Z=25
            return Character.toUpperCase(ch) - 'A';
        } else if (Character.isDigit(ch)) {
            // angka: 0=26, ..., 9=35
            return ch - '0' + 26;
        } else {
            // karakter lain diabaikan
            return -1;
        }
    }
    
    // konversi angka ke karakter
    public static String numberToChar(int number) {
        if (number >= 0 && number <= 25) {
            return String.valueOf((char) (number + 'A'));
        } else if (number >= 26 && number <= 35) {
            return String.valueOf((char) (number - 26 + '0'));
        } else {
            return "?"; //karakter lain
        }
    }
    
    // konversi teks ke angka
    public static int[] textToNumbers(String text) {
        text = text.toUpperCase().replaceAll("[^A-Z0-9]", "");
        List<Integer> numbersList = new ArrayList<>();
        
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            int num = charToNumber(ch);
            if (num != -1) {
                numbersList.add(num);
            }
        }
        
        // konversi list ke array
        int[] numbers = new int[numbersList.size()];
        for (int i = 0; i < numbersList.size(); i++) {
            numbers[i] = numbersList.get(i);
        }
        return numbers;
    }
    
    // Kkonversi angka ke teks 
    public static String numbersToText(int[] numbers) {
        StringBuilder text = new StringBuilder();
        for (int number : numbers) {
            text.append(numberToChar(number));
        }
        return text.toString();
    }
    
    // parse matriks kunci dari input dengan validasi 
    public static int[][] parseKeyMatrix(String keyText, int size) {
        String[] rows = keyText.split("\n");
        
        // validasi jumlah baris
        if (rows.length < size) {
            throw new IllegalArgumentException("Kunci matriks " + size + "x" + size + " membutuhkan " + size + " baris");
        }
        
        int[][] matrix = new int[size][size];
        
        for (int i = 0; i < size; i++) {
            if (i < rows.length) {
                String[] values = rows[i].trim().split("\\s+");
                
                // validasi jumlah kolom per baris
                if (values.length < size) {
                    throw new IllegalArgumentException("Baris " + (i+1) + " hanya memiliki " + values.length + " elemen, butuh " + size + " elemen");
                }
                
                for (int j = 0; j < size; j++) {
                    if (j < values.length && !values[j].isEmpty()) 
                    {
                        try {
                            // oba parse sebagai angka 
                            matrix[i][j] = Integer.parseInt(values[j]);
                        } catch (NumberFormatException e) {
                            // coba sebagai huruf
                            if (values[j].length() == 1) 
                            {
                                char ch = values[j].charAt(0);
                                if (Character.isLetter(ch)) 
                                {
                                    matrix[i][j] = letterToNumber(ch);
                                } 
                                else 
                                {
                                    throw new IllegalArgumentException("Karakter '" + values[j] + "' tidak valid. Harus angka atau huruf");
                                }
                            } 
                            else 
                            {
                                throw new IllegalArgumentException("Nilai '" + values[j] + "' tidak valid");
                            }
                        }
                    } 
                    else 
                    {
                        throw new IllegalArgumentException("Elemen matriks tidak boleh kosong");
                    }
                }
            }
        }
        return matrix;
    }
    
    // validasi matriks kunci
    public static boolean isValidKey(int[][] keyMatrix, int mod) {
        int det = determinant(keyMatrix);
        return gcd(det, mod) == 1;
    }
    
    // hitung determinan matriks 2x2
    public static int determinant2x2(int[][] matrix) {
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
    }
    
    // hitung determinan matriks 3x3
    public static int determinant3x3(int[][] matrix) {
        return matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1])
             - matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0])
             + matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]);
    }
    
    // hitung determinan berdasarkan ukuran
    public static int determinant(int[][] matrix) {
        if (matrix.length == 2) {
            return determinant2x2(matrix);
        } else {
            return determinant3x3(matrix);
        }
    }
    
    // cari GCD 
    public static int gcd(int a, int b) {
        if (b == 0) return Math.abs(a);
        return gcd(b, a % b);
    }
    
    // class utk simpan hasil enkripsi 
    public static class EncryptionResultWithPadding {
        private final String ciphertext;
        private final List<String> steps;
        private final int paddingCount;
        private final String originalPlaintext;
        
        public EncryptionResultWithPadding(String ciphertext, List<String> steps, int paddingCount, String originalPlaintext) {
            this.ciphertext = ciphertext;
            this.steps = steps;
            this.paddingCount = paddingCount;
            this.originalPlaintext = originalPlaintext;
        }
        
        public String getCiphertext() { return ciphertext; }
        public List<String> getSteps() { return steps; }
        public int getPaddingCount() { return paddingCount; }
        public String getOriginalPlaintext() { return originalPlaintext; }
    }
    
    // enkripsi Hill Cipher 
    public static String encrypt(String plaintext, int[][] keyMatrix) {
        int size = keyMatrix.length;
        int[] numbers = textToNumbers(plaintext);
        
        // Ttambah padding kalau perlu
        int paddingNeeded = (size - (numbers.length % size)) % size;
        int[] paddedNumbers = new int[numbers.length + paddingNeeded];
        System.arraycopy(numbers, 0, paddedNumbers, 0, numbers.length);
        for (int i = numbers.length; i < paddedNumbers.length; i++) {
            paddedNumbers[i] = 23; // Padding dengan 'X' (X=23 karena A=0)
        }
        
        // enkripsi per blok
        List<Integer> resultNumbers = new ArrayList<>();
        for (int i = 0; i < paddedNumbers.length; i += size) {
            int[] block = new int[size];
            System.arraycopy(paddedNumbers, i, block, 0, size);
            
            int[] encryptedBlock = multiplyMatrix(keyMatrix, block);
            for (int num : encryptedBlock) {
                resultNumbers.add(num);
            }
        }
        
        // konversi ke array primitif
        int[] resultArray = new int[resultNumbers.size()];
        for (int i = 0; i < resultNumbers.size(); i++) {
            resultArray[i] = resultNumbers.get(i);
        }
        
        return numbersToText(resultArray);
    }
  
    public static EncryptionResultWithPadding encryptWithDetails(String plaintext, int[][] keyMatrix) {
        int size = keyMatrix.length;
        String originalPlaintext = plaintext; // Simpan plaintext asli
        
        // simpan semua langkah untuk ditampilkan
        List<String> steps = new ArrayList<>();
        steps.add("PROSES ENKRIPSI HILL CIPHER");
        steps.add("============================");
        steps.add("Plaintext: " + plaintext);
        steps.add("");
        
        // tampilkan matriks kunci
        steps.add("Kunci Matriks " + size + "x" + size + ":");
        for (int i = 0; i < size; i++) 
        {
            StringBuilder row = new StringBuilder();
            for (int j = 0; j < size; j++) 
            {
                row.append(String.format("%2d", keyMatrix[i][j])).append(" ");
            }
            steps.add(row.toString());
        }
        
        // tampilkan determinan
        int det = determinant(keyMatrix);
        steps.add("Determinan: " + det);
        steps.add("GCD(" + det + ", 26) = " + gcd(det, 26));
        steps.add("");
        
        // konversi plaintext ke angka
        int[] numbers = textToNumbers(plaintext);
        StringBuilder numberStep = new StringBuilder("Plaintext -> Angka: ");
        for (int i = 0; i < numbers.length; i++) {
            if (i < plaintext.length()) 
            {
                char ch = plaintext.charAt(i);
                numberStep.append(ch).append(" = ").append(numbers[i]);
            } 
            else 
            {
                numberStep.append("X = ").append(numbers[i]);
            }
            if (i < numbers.length - 1) numberStep.append(", ");
        }
        steps.add(numberStep.toString());
        steps.add("");
        
        int paddingNeeded = (size - (numbers.length % size)) % size;
        int[] paddedNumbers = new int[numbers.length + paddingNeeded];
        System.arraycopy(numbers, 0, paddedNumbers, 0, numbers.length);
        
        if (paddingNeeded > 0) 
        {
            steps.add("Penambahan padding (" + paddingNeeded + " karakter 'X'):");
            for (int i = numbers.length; i < paddedNumbers.length; i++) 
            {
                paddedNumbers[i] = 23; // 'X' = 23 (karena A=0, B=1, ..., X=23)
            }
            StringBuilder paddedStep = new StringBuilder("Setelah padding: ");
            for (int i = 0; i < paddedNumbers.length; i++) 
            {
                paddedStep.append(paddedNumbers[i]);
                if (i < paddedNumbers.length - 1) paddedStep.append(", ");
            }
            steps.add(paddedStep.toString());
        } 
        else 
        {
            steps.add("Tidak perlu padding");
        }
        steps.add("");
        
        steps.add("MATRIKS PLAINTEXT:");
        steps.add("=================");

        // tampilkan sebagai matriks 2 kolom
        for (int i = 0; i < paddedNumbers.length; i += 2) 
        {
            StringBuilder row = new StringBuilder();
            row.append("[");
            row.append(String.format("%2d", paddedNumbers[i])).append("  ");
            if (i + 1 < paddedNumbers.length) 
            {
                row.append(String.format("%2d", paddedNumbers[i + 1]));
            }
            row.append("]");
            steps.add(row.toString());
        }
        steps.add("");

        // tampilkan penjelasan per blok
        steps.add("PEMBAGIAN BLOK:");
        steps.add("==============");
        int blockCount = paddedNumbers.length / size;
        for (int i = 0; i < blockCount; i++) {
            StringBuilder blockInfo = new StringBuilder();
            blockInfo.append("Blok ").append(i + 1).append(": [");
            for (int j = 0; j < size; j++) {
                int index = i * size + j;
                blockInfo.append(paddedNumbers[index]);
                if (j < size - 1) blockInfo.append(", ");
            }
            blockInfo.append("]");
            steps.add(blockInfo.toString());
        }
        steps.add("");
        
        // enkripsi per blok
        List<Integer> resultNumbers = new ArrayList<>();
        steps.add("PROSES ENKRIPSI PER BLOK:");
        steps.add("========================");
        
        for (int i = 0; i < paddedNumbers.length; i += size) {
            int[] block = new int[size];
            System.arraycopy(paddedNumbers, i, block, 0, size);
            
            // tampilkan hasil per blok
            StringBuilder blockWithChars = new StringBuilder();
            blockWithChars.append("Blok ").append(i/size + 1).append(": [");
            for (int j = 0; j < size; j++) {
                blockWithChars.append(block[j]);
                if (j < size - 1) blockWithChars.append(", ");
            }
            blockWithChars.append("] --> ");
            for (int j = 0; j < size; j++) {
                blockWithChars.append(numberToChar(block[j]));
                if (j < size - 1) blockWithChars.append(" ");
            }
            steps.add(blockWithChars.toString());
            
            // tampilkan perkalian matriks
            steps.add("Perkalian dengan matriks kunci:");
            int[] encryptedBlock = multiplyMatrixWithDetails(keyMatrix, block, steps);
            
            // tampilkan hasil blok dengan karakter
            StringBuilder resultWithChars = new StringBuilder();
            resultWithChars.append("Hasil blok ").append(i/size + 1).append(": [");
            for (int j = 0; j < encryptedBlock.length; j++) {
                resultWithChars.append(encryptedBlock[j]);
                if (j < encryptedBlock.length - 1) resultWithChars.append(", ");
            }
            resultWithChars.append("] --> ");
            for (int j = 0; j < encryptedBlock.length; j++) {
                resultWithChars.append(numberToChar(encryptedBlock[j]));
                if (j < encryptedBlock.length - 1) resultWithChars.append(" ");
            }
            steps.add(resultWithChars.toString());
            steps.add("");
            
            for (int num : encryptedBlock) {
                resultNumbers.add(num);
            }
        }
        
        // konversi ke array primitif
        int[] resultArray = new int[resultNumbers.size()];
        for (int i = 0; i < resultNumbers.size(); i++) {
            resultArray[i] = resultNumbers.get(i);
        }
        
        String ciphertext = numbersToText(resultArray);
        steps.add("Ciphertext akhir: " + ciphertext);
        
        return new EncryptionResultWithPadding(ciphertext, steps, paddingNeeded, originalPlaintext);
    }
   
    public static EncryptionResultWithPadding encryptWithDetails3x3(String plaintext, int[][] keyMatrix) {
        int size = keyMatrix.length;
        if (size != 3) {
            throw new IllegalArgumentException("Method ini hanya untuk matriks 3x3");
        }
        
        String originalPlaintext = plaintext; // Simpan plaintext asli
        
        // simpan semua langkah untuk ditampilkan
        List<String> steps = new ArrayList<>();
        steps.add("PROSES ENKRIPSI HILL CIPHER 3x3");
        steps.add("================================");
        steps.add("Plaintext: " + plaintext);
        steps.add("");
        
        // tampilkan matriks kunci
        steps.add("Kunci Matriks 3x3:");
        for (int i = 0; i < size; i++) {
            StringBuilder row = new StringBuilder();
            for (int j = 0; j < size; j++) {
                row.append(String.format("%2d", keyMatrix[i][j])).append(" ");
            }
            steps.add(row.toString());
        }
        
        // tampilkan determinan
        int det = determinant3x3(keyMatrix);
        steps.add("Determinan: " + det);
        steps.add("GCD(" + det + ", 26) = " + gcd(det, 26));
        steps.add("");
        
        // konversi plaintext ke angka
        int[] numbers = textToNumbers(plaintext);
        StringBuilder numberStep = new StringBuilder("Plaintext -> Angka: ");
        for (int i = 0; i < numbers.length; i++) 
        {
            if (i < plaintext.length()) 
            {
                char ch = plaintext.charAt(i);
                numberStep.append(ch).append(" = ").append(numbers[i]);
            } 
            else 
            {
                numberStep.append("X = ").append(numbers[i]);
            }
            if (i < numbers.length - 1) numberStep.append(", ");
        }
        steps.add(numberStep.toString());
        steps.add("");
        
        // tambah padding jika perlu
        int paddingNeeded = (3 - (numbers.length % 3)) % 3;
        int[] paddedNumbers = new int[numbers.length + paddingNeeded];
        System.arraycopy(numbers, 0, paddedNumbers, 0, numbers.length);
        
        if (paddingNeeded > 0) 
        {
            steps.add("Penambahan padding (" + paddingNeeded + " karakter 'X'):");
            for (int i = numbers.length; i < paddedNumbers.length; i++) 
            {
                paddedNumbers[i] = 23; // 'X' = 23
            }
            StringBuilder paddedStep = new StringBuilder("Setelah padding: ");
            for (int i = 0; i < paddedNumbers.length; i++) 
            {
                paddedStep.append(paddedNumbers[i]);
                if (i < paddedNumbers.length - 1) paddedStep.append(", ");
            }
            steps.add(paddedStep.toString());
        } 
        else 
        {
            steps.add("Tidak perlu padding");
        }
        steps.add("");
        
        steps.add("MATRIKS PLAINTEXT (3 kolom):");
        steps.add("============================");

        // tampilkan sebagai matriks 3 kolom
        for (int i = 0; i < paddedNumbers.length; i += 3) {
            StringBuilder row = new StringBuilder();
            row.append("[");
            for (int j = 0; j < 3; j++) 
            {
                int index = i + j;
                if (index < paddedNumbers.length) 
                {
                    row.append(String.format("%2d", paddedNumbers[index]));
                } 
                else 
                {
                    row.append("  "); 
                }
                if (j < 2) row.append("  ");
            }
            row.append("]");
            steps.add(row.toString());
        }
        steps.add("");

        steps.add("PEMBAGIAN BLOK (3 karakter per blok):");
        steps.add("====================================");
        int blockCount = paddedNumbers.length / 3;
        for (int i = 0; i < blockCount; i++) 
        {
            StringBuilder blockInfo = new StringBuilder();
            blockInfo.append("Blok ").append(i + 1).append(": [");
            for (int j = 0; j < 3; j++) 
            {
                int index = i * 3 + j;
                blockInfo.append(paddedNumbers[index]);
                if (j < 2) blockInfo.append(", ");
            }
            blockInfo.append("]");
            steps.add(blockInfo.toString());
        }
        steps.add("");
        
        // enkripsi per blok
        List<Integer> resultNumbers = new ArrayList<>();
        steps.add("PROSES ENKRIPSI PER BLOK:");
        steps.add("========================");
        
        for (int i = 0; i < paddedNumbers.length; i += 3) {
            int[] block = new int[3];
            System.arraycopy(paddedNumbers, i, block, 0, 3);
            
            // tampilkan blok dengan karakter (huruf)
            StringBuilder blockWithChars = new StringBuilder();
            blockWithChars.append("Blok ").append(i/3 + 1).append(": [");
            for (int j = 0; j < 3; j++) {
                blockWithChars.append(block[j]);
                if (j < 2) blockWithChars.append(", ");
            }
            blockWithChars.append("] --> ");
            for (int j = 0; j < 3; j++) {
                blockWithChars.append(numberToChar(block[j]));
                if (j < 2) blockWithChars.append(" ");
            }
            steps.add(blockWithChars.toString());
            
            // tampilkan perkalian matriks
            steps.add("Perkalian dengan matriks kunci:");
            int[] encryptedBlock = multiplyMatrix3x3WithDetails(keyMatrix, block, steps);
            
            // tampilkan hasil blok dengan karakter (huruf)
            StringBuilder resultWithChars = new StringBuilder();
            resultWithChars.append("Hasil blok ").append(i/3 + 1).append(": [");
            for (int j = 0; j < encryptedBlock.length; j++) {
                resultWithChars.append(encryptedBlock[j]);
                if (j < 2) resultWithChars.append(", ");
            }
            resultWithChars.append("] --> ");
            for (int j = 0; j < encryptedBlock.length; j++) {
                resultWithChars.append(numberToChar(encryptedBlock[j]));
                if (j < 2) resultWithChars.append(" ");
            }
            steps.add(resultWithChars.toString());
            steps.add("");
            
            for (int num : encryptedBlock) {
                resultNumbers.add(num);
            }
        }
        
        // konversi ke array primitif
        int[] resultArray = new int[resultNumbers.size()];
        for (int i = 0; i < resultNumbers.size(); i++) {
            resultArray[i] = resultNumbers.get(i);
        }
        
        String ciphertext = numbersToText(resultArray);
        steps.add("Ciphertext akhir: " + ciphertext);
        
        return new EncryptionResultWithPadding(ciphertext, steps, paddingNeeded, originalPlaintext);
    }
   
    public static DecryptionResult decryptWithDetails(String ciphertext, int[][] keyMatrix, int paddingCount) {
        int size = keyMatrix.length;
        
        // simpan semua langkah untuk ditampilkan
        List<String> steps = new ArrayList<>();
        steps.add("PROSES DEKRIPSI HILL CIPHER");
        steps.add("============================");
        steps.add("Ciphertext: " + ciphertext);
        if (paddingCount > 0) {
            steps.add("Jumlah padding yang akan dihapus: " + paddingCount + " karakter");
        }
        steps.add("");
        
        // tampilkan matriks kunci
        steps.add("Kunci Matriks " + size + "x" + size + ":");
        for (int i = 0; i < size; i++) {
            StringBuilder row = new StringBuilder();
            for (int j = 0; j < size; j++) {
                row.append(String.format("%2d", keyMatrix[i][j])).append(" ");
            }
            steps.add(row.toString());
        }
        
        // tampilkan determinan
        int det = determinant(keyMatrix);
        steps.add("Determinan: " + det);
        steps.add("GCD(" + det + ", 26) = " + gcd(det, 26));
        steps.add("");
        
        // cari matriks invers
        steps.add("MENCARI MATRIKS INVERS:");
        steps.add("======================");
        int[][] inverseMatrix = findInverseMatrixWithDetails(keyMatrix, 26, steps);
        
        steps.add("");
        
        // konversi ciphertext ke angka
        int[] numbers = textToNumbers(ciphertext);
        StringBuilder numberStep = new StringBuilder("Ciphertext -> Angka: ");
        for (int i = 0; i < numbers.length; i++) {
            if (i < ciphertext.length()) {
                char ch = ciphertext.charAt(i);
                numberStep.append(ch).append(" = ").append(numbers[i]);
            }
            if (i < numbers.length - 1) numberStep.append(", ");
        }
        steps.add(numberStep.toString());
        steps.add("");
        
        steps.add("MATRIKS CIPHERTEXT:");
        steps.add("===================");

        // tampil sebagai matriks
        if (size == 2) {
            // tampilkan 2 kolom untuk matriks 2x2
            for (int i = 0; i < numbers.length; i += 2) 
            {
                StringBuilder row = new StringBuilder();
                row.append("[");
                row.append(String.format("%2d", numbers[i])).append("  ");
                if (i + 1 < numbers.length) 
                {
                    row.append(String.format("%2d", numbers[i + 1]));
                }
                row.append("]");
                steps.add(row.toString());
            }
        } 
        else 
        {
            // tampilkan 3 kolom untuk matriks 3x3
            for (int i = 0; i < numbers.length; i += 3) 
            {
                StringBuilder row = new StringBuilder();
                row.append("[");
                for (int j = 0; j < 3; j++) 
                {
                    int index = i + j;
                    if (index < numbers.length) 
                    {
                        row.append(String.format("%2d", numbers[index]));
                    }
                    if (j < 2) row.append("  ");
                }
                row.append("]");
                steps.add(row.toString());
            }
        }
        steps.add("");

        // tampilkan penjelasan per blok
        steps.add("PEMBAGIAN BLOK:");
        steps.add("==============");
        int blockCount = numbers.length / size;
        for (int i = 0; i < blockCount; i++) {
            
            StringBuilder blockInfo = new StringBuilder();
            blockInfo.append("Blok ").append(i + 1).append(": [");
            for (int j = 0; j < size; j++) 
            {
                int index = i * size + j;
                blockInfo.append(numbers[index]);
                if (j < size - 1) blockInfo.append(", ");
            }
            blockInfo.append("]");
            steps.add(blockInfo.toString());
        }
        steps.add("");
        
        // dekripsi per blok
        List<Integer> resultNumbers = new ArrayList<>();
        steps.add("PROSES DEKRIPSI PER BLOK:");
        steps.add("========================");
        
        for (int i = 0; i < numbers.length; i += size) {
            int[] block = new int[size];
            System.arraycopy(numbers, i, block, 0, size);
            
            // tampilkan blok dengan karakter (huruf/angka)
            StringBuilder blockWithChars = new StringBuilder();
            blockWithChars.append("Blok ").append(i/size + 1).append(": [");
            for (int j = 0; j < size; j++) {
                blockWithChars.append(block[j]);
                if (j < size - 1) blockWithChars.append(", ");
            }
            blockWithChars.append("] --> ");
            for (int j = 0; j < size; j++) {
                blockWithChars.append(numberToChar(block[j]));
                if (j < size - 1) blockWithChars.append(" ");
            }
            steps.add(blockWithChars.toString());
            
            // tampilkan perkalian matriks
            steps.add("Perkalian dengan matriks invers:");
            int[] decryptedBlock = multiplyMatrixWithDetails(inverseMatrix, block, steps);
            
            // tampilkan hasil blok dengan karakter
            StringBuilder resultWithChars = new StringBuilder();
            resultWithChars.append("Hasil blok ").append(i/size + 1).append(": [");
            for (int j = 0; j < decryptedBlock.length; j++) {
                resultWithChars.append(decryptedBlock[j]);
                if (j < decryptedBlock.length - 1) resultWithChars.append(", ");
            }
            resultWithChars.append("] --> ");
            for (int j = 0; j < decryptedBlock.length; j++) {
                resultWithChars.append(numberToChar(decryptedBlock[j]));
                if (j < decryptedBlock.length - 1) resultWithChars.append(" ");
            }
            steps.add(resultWithChars.toString());
            steps.add("");
            
            for (int num : decryptedBlock) {
                resultNumbers.add(num);
            }
        }
        
        // konversi ke array primitif
        int[] resultArray = new int[resultNumbers.size()];
        for (int i = 0; i < resultNumbers.size(); i++) {
            resultArray[i] = resultNumbers.get(i);
        }
        
        String decryptedWithPadding = numbersToText(resultArray);
        
        String plaintext;
        if (paddingCount > 0 && decryptedWithPadding.length() >= paddingCount) {
            plaintext = decryptedWithPadding.substring(0, decryptedWithPadding.length() - paddingCount);
            steps.add("Hasil dekripsi dengan padding: " + decryptedWithPadding);
            steps.add("Menghapus " + paddingCount + " karakter padding: '" + 
                     decryptedWithPadding.substring(decryptedWithPadding.length() - paddingCount) + "'");
        } else {
            plaintext = decryptedWithPadding;
        }
        
        steps.add("Plaintext akhir: " + plaintext);
        
        return new DecryptionResult(plaintext, steps);
    }
    
    // dekripsi 3x3 
    public static DecryptionResult decryptWithDetails3x3(String ciphertext, int[][] keyMatrix, int paddingCount) {
        int size = keyMatrix.length;
        if (size != 3) {
            throw new IllegalArgumentException("Method ini hanya untuk matriks 3x3");
        }
        
        // simpan semua langkah untuk ditampilkan
        List<String> steps = new ArrayList<>();
        steps.add("PROSES DEKRIPSI HILL CIPHER 3x3");
        steps.add("================================");
        steps.add("Ciphertext: " + ciphertext);
        if (paddingCount > 0) {
            steps.add("Jumlah padding yang akan dihapus: " + paddingCount + " karakter");
        }
        steps.add("");
        
        // tampilkan matriks kunci
        steps.add("Kunci Matriks 3x3:");
        for (int i = 0; i < size; i++) {
            StringBuilder row = new StringBuilder();
            for (int j = 0; j < size; j++) {
                row.append(String.format("%2d", keyMatrix[i][j])).append(" ");
            }
            steps.add(row.toString());
        }
        
        // tampilkan determinan
        int det = determinant3x3(keyMatrix);
        steps.add("Determinan: " + det);
        steps.add("GCD(" + det + ", 26) = " + gcd(det, 26));
        steps.add("");
        
        // cari matriks invers
        steps.add("MENCARI MATRIKS INVERS:");
        steps.add("======================");
        int[][] inverseMatrix = findInverseMatrix3x3WithDetails(keyMatrix, 26, steps);
        
        steps.add("");
        
        // konversi ciphertext ke angka
        int[] numbers = textToNumbers(ciphertext);
        StringBuilder numberStep = new StringBuilder("Ciphertext -> Angka: ");
        for (int i = 0; i < numbers.length; i++) {
            if (i < ciphertext.length()) {
                char ch = ciphertext.charAt(i);
                numberStep.append(ch).append(" = ").append(numbers[i]);
            }
            if (i < numbers.length - 1) numberStep.append(", ");
        }
        steps.add(numberStep.toString());
        steps.add("");
        
        steps.add("MATRIKS CIPHERTEXT (3 kolom):");
        steps.add("=============================");

        // tampilkan sebagai matriks 3 kolom
        for (int i = 0; i < numbers.length; i += 3) {
            StringBuilder row = new StringBuilder();
            row.append("[");
            for (int j = 0; j < 3; j++) {
                int index = i + j;
                if (index < numbers.length) {
                    row.append(String.format("%2d", numbers[index]));
                }
                if (j < 2) row.append("  ");
            }
            row.append("]");
            steps.add(row.toString());
        }
        steps.add("");

        // tampilkan penjelasan per blok
        steps.add("PEMBAGIAN BLOK (3 karakter per blok):");
        steps.add("====================================");
        int blockCount = numbers.length / 3;
        for (int i = 0; i < blockCount; i++) 
        {
            StringBuilder blockInfo = new StringBuilder();
            blockInfo.append("Blok ").append(i + 1).append(": [");
            for (int j = 0; j < 3; j++) 
            {
                int index = i * 3 + j;
                blockInfo.append(numbers[index]);
                if (j < 2) blockInfo.append(", ");
            }
            blockInfo.append("]");
            steps.add(blockInfo.toString());
        }
        steps.add("");
        
        // dekripsi per blok
        List<Integer> resultNumbers = new ArrayList<>();
        steps.add("PROSES DEKRIPSI PER BLOK:");
        steps.add("========================");
        
        for (int i = 0; i < numbers.length; i += 3) {
            int[] block = new int[3];
            System.arraycopy(numbers, i, block, 0, 3);
            
            // tampilkan blok dengan karakter
            StringBuilder blockWithChars = new StringBuilder();
            blockWithChars.append("Blok ").append(i/3 + 1).append(": [");
            for (int j = 0; j < 3; j++) {
                blockWithChars.append(block[j]);
                if (j < 2) blockWithChars.append(", ");
            }
            blockWithChars.append("] --> ");
            for (int j = 0; j < 3; j++) {
                blockWithChars.append(numberToChar(block[j]));
                if (j < 2) blockWithChars.append(" ");
            }
            steps.add(blockWithChars.toString());
            
            // tampilkan perkalian matriks
            steps.add("Perkalian dengan matriks invers:");
            int[] decryptedBlock = multiplyMatrix3x3WithDetails(inverseMatrix, block, steps);
            
            // tampilkan hasil blok dengan karakter
            StringBuilder resultWithChars = new StringBuilder();
            resultWithChars.append("Hasil blok ").append(i/3 + 1).append(": [");
            for (int j = 0; j < decryptedBlock.length; j++) {
                resultWithChars.append(decryptedBlock[j]);
                if (j < 2) resultWithChars.append(", ");
            }
            resultWithChars.append("] --> ");
            for (int j = 0; j < decryptedBlock.length; j++) {
                resultWithChars.append(numberToChar(decryptedBlock[j]));
                if (j < 2) resultWithChars.append(" ");
            }
            steps.add(resultWithChars.toString());
            steps.add("");
            
            for (int num : decryptedBlock) {
                resultNumbers.add(num);
            }
        }
        
        // konversi ke array primitif
        int[] resultArray = new int[resultNumbers.size()];
        for (int i = 0; i < resultNumbers.size(); i++) {
            resultArray[i] = resultNumbers.get(i);
        }
        
        String decryptedWithPadding = numbersToText(resultArray);
       
        String plaintext;
        if (paddingCount > 0 && decryptedWithPadding.length() >= paddingCount) {
            plaintext = decryptedWithPadding.substring(0, decryptedWithPadding.length() - paddingCount);
            steps.add("Hasil dekripsi dengan padding: " + decryptedWithPadding);
            steps.add("Menghapus " + paddingCount + " karakter padding: '" + 
                     decryptedWithPadding.substring(decryptedWithPadding.length() - paddingCount) + "'");
        } else {
            plaintext = decryptedWithPadding;
        }
        
        steps.add("Plaintext akhir: " + plaintext);
        
        return new DecryptionResult(plaintext, steps);
    }
    
    // dekripsi biasa 
    public static String decrypt(String ciphertext, int[][] keyMatrix) {
        int size = keyMatrix.length;
        int[] numbers = textToNumbers(ciphertext);
        
        // cari matriks invers
        int[][] inverseMatrix = findInverseMatrix(keyMatrix, 26);
        
        // dekripsi per blok
        List<Integer> resultNumbers = new ArrayList<>();
        for (int i = 0; i < numbers.length; i += size) {
            int[] block = new int[size];
            System.arraycopy(numbers, i, block, 0, size);
            
            int[] decryptedBlock = multiplyMatrix(inverseMatrix, block);
            for (int num : decryptedBlock) {
                resultNumbers.add(num);
            }
        }
        
        // konversi ke array primitif
        int[] resultArray = new int[resultNumbers.size()];
        for (int i = 0; i < resultNumbers.size(); i++) {
            resultArray[i] = resultNumbers.get(i);
        }
        
        return numbersToText(resultArray);
    }
    
    // method bantu untuk cari invers matriks dengan detail
    private static int[][] findInverseMatrixWithDetails(int[][] matrix, int mod, List<String> steps) {
        int size = matrix.length;
        int det = determinant(matrix);
        
        steps.add("Determinan matriks: " + det);
        
        // cari invers determinan modulo 26
        int detInverse = -1;
        for (int i = 0; i < mod; i++) {
            if ((det * i) % mod == 1) {
                detInverse = i;
                break;
            }
        }
        
        if (detInverse == -1) {
            throw new IllegalArgumentException("Matriks tidak memiliki invers modulo " + mod);
        }
        
        steps.add("Invers determinan modulo 26: " + detInverse);
        steps.add("(Karena " + det + " × " + detInverse + " ≡ 1 mod 26)");
        
        if (size == 2) {
            return inverse2x2WithDetails(matrix, detInverse, mod, steps);
        } else {
            return inverse3x3WithDetails(matrix, detInverse, mod, steps);
        }
    }
    
    // invers matriks 2x2 
    private static int[][] inverse2x2WithDetails(int[][] matrix, int detInverse, int mod, List<String> steps) {
        steps.add("");
        steps.add("Rumus invers matriks 2x2:");
        steps.add("[a b]⁻¹ = (1/det) × [d -b]");
        steps.add("[c d]          [-c  a]");
        steps.add("");
        
        int[][] inverse = new int[2][2];
        inverse[0][0] = Math.floorMod(matrix[1][1] * detInverse, mod);
        inverse[0][1] = Math.floorMod(-matrix[0][1] * detInverse, mod);
        inverse[1][0] = Math.floorMod(-matrix[1][0] * detInverse, mod);
        inverse[1][1] = Math.floorMod(matrix[0][0] * detInverse, mod);
        
        steps.add("Perhitungan:");
        steps.add("inverse[0][0] = (" + matrix[1][1] + " × " + detInverse + ") mod 26 = " + inverse[0][0]);
        steps.add("inverse[0][1] = (-" + matrix[0][1] + " × " + detInverse + ") mod 26 = " + inverse[0][1]);
        steps.add("inverse[1][0] = (-" + matrix[1][0] + " × " + detInverse + ") mod 26 = " + inverse[1][0]);
        steps.add("inverse[1][1] = (" + matrix[0][0] + " × " + detInverse + ") mod 26 = " + inverse[1][1]);
        steps.add("");
        steps.add("Matriks Invers:");
        steps.add("[" + inverse[0][0] + " " + inverse[0][1] + "]");
        steps.add("[" + inverse[1][0] + " " + inverse[1][1] + "]");
        
        return inverse;
    }
    
    // invers matriks 3x3 
    private static int[][] findInverseMatrix3x3WithDetails(int[][] matrix, int mod, List<String> steps) {
        int det = determinant3x3(matrix);
        
        steps.add("Determinan matriks: " + det);
        
        // cari invers determinan modulo 26
        int detInverse = -1;
        for (int i = 0; i < mod; i++) {
            if ((det * i) % mod == 1) {
                detInverse = i;
                break;
            }
        }
        
        if (detInverse == -1) {
            throw new IllegalArgumentException("Matriks tidak memiliki invers modulo " + mod);
        }
        
        steps.add("Invers determinan modulo 26: " + detInverse);
        steps.add("(Karena " + det + " × " + detInverse + " ≡ 1 mod 26)");
        
        return inverse3x3WithDetails(matrix, detInverse, mod, steps);
    }
    
    // invers matriks 3x3 
    private static int[][] inverse3x3WithDetails(int[][] matrix, int detInverse, int mod, List<String> steps) {
        steps.add("");
        steps.add("Menghitung matriks kofaktor:");
        
        int[][] cofactor = new int[3][3];
        cofactor[0][0] = Math.floorMod(matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1], mod);
        cofactor[0][1] = Math.floorMod(-(matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]), mod);
        cofactor[0][2] = Math.floorMod(matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0], mod);
        cofactor[1][0] = Math.floorMod(-(matrix[0][1] * matrix[2][2] - matrix[0][2] * matrix[2][1]), mod);
        cofactor[1][1] = Math.floorMod(matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0], mod);
        cofactor[1][2] = Math.floorMod(-(matrix[0][0] * matrix[2][1] - matrix[0][1] * matrix[2][0]), mod);
        cofactor[2][0] = Math.floorMod(matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1], mod);
        cofactor[2][1] = Math.floorMod(-(matrix[0][0] * matrix[1][2] - matrix[0][2] * matrix[1][0]), mod);
        cofactor[2][2] = Math.floorMod(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0], mod);
        
        steps.add("Matriks Kofaktor:");
        for (int i = 0; i < 3; i++) {
            StringBuilder row = new StringBuilder();
            for (int j = 0; j < 3; j++) {
                row.append(String.format("%4d", cofactor[i][j])).append(" ");
            }
            steps.add(row.toString());
        }
        
        steps.add("");
        steps.add("Transpose matriks kofaktor (Adjoint):");
        int[][] inverse = new int[3][3];
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                inverse[i][j] = Math.floorMod(cofactor[j][i] * detInverse, mod);
            }
        }
        
        steps.add("Matriks Invers (Adjoint × detInverse):");
        for (int i = 0; i < 3; i++) {
            StringBuilder row = new StringBuilder();
            for (int j = 0; j < 3; j++) {
                row.append(String.format("%4d", inverse[i][j])).append(" ");
            }
            steps.add(row.toString());
        }
        
        return inverse;
    }
    
    // method untuk perkalian matriks 3x3 
    private static int[] multiplyMatrix3x3WithDetails(int[][] matrix, int[] vector, List<String> steps) {
        int[] result = new int[3];
        
        for (int i = 0; i < 3; i++) {
            StringBuilder calculation = new StringBuilder();
            calculation.append("  Baris ").append(i+1).append(": (");
            
            int sum = 0;
            for (int j = 0; j < 3; j++) {
                calculation.append(matrix[i][j]).append("×").append(vector[j]);
                sum += matrix[i][j] * vector[j];
                if (j < 2) calculation.append(" + ");
            }
            
            calculation.append(") = ").append(sum);
            
            // tampilkan perhitungan 
            StringBuilder detailCalc = new StringBuilder();
            detailCalc.append("    = ");
            for (int j = 0; j < 3; j++) {
                detailCalc.append("(").append(matrix[i][j]).append("×").append(vector[j]).append(")");
                if (j < 2) detailCalc.append(" + ");
            }
            detailCalc.append(" = ").append(sum);
            steps.add(detailCalc.toString());
            
            // mod 26
            int modResult = Math.floorMod(sum, 26);
            
            calculation.append(" mod 26 = ").append(modResult);
            steps.add(calculation.toString());
            steps.add("");
            
            result[i] = modResult;
        }
        
        return result;
    }
    
    // method untuk perkalian matriks 
    private static int[] multiplyMatrixWithDetails(int[][] matrix, int[] vector, List<String> steps) {
        int size = matrix.length;
        int[] result = new int[size];
        
        for (int i = 0; i < size; i++) {
            StringBuilder calculation = new StringBuilder();
            calculation.append("  Baris ").append(i+1).append(": (");
            
            int sum = 0;
            for (int j = 0; j < size; j++) {
                calculation.append(matrix[i][j]).append("×").append(vector[j]);
                if (j < size - 1) calculation.append(" + ");
                sum += matrix[i][j] * vector[j];
            }
            
            calculation.append(") mod 26 = ").append(sum).append(" mod 26 = ").append(Math.floorMod(sum, 26));
            steps.add(calculation.toString());
            
            result[i] = Math.floorMod(sum, 26);
        }
        
        return result;
    }
    
    // perkalian matriks dengan vektor
    private static int[] multiplyMatrix(int[][] matrix, int[] vector) {
        int size = matrix.length;
        int[] result = new int[size];
        
        for (int i = 0; i < size; i++) {
            int sum = 0;
            for (int j = 0; j < size; j++) {
                sum += matrix[i][j] * vector[j];
            }
            result[i] = Math.floorMod(sum, 26); // Mod 26
        }
        
        return result;
    }
    
    // cari matriks invers modulo 26
    public static int[][] findInverseMatrix(int[][] matrix, int mod) {
        int size = matrix.length;
        int det = determinant(matrix);
        
        // cari invers determinan modulo 26
        int detInverse = -1;
        for (int i = 0; i < mod; i++) {
            if ((det * i) % mod == 1) {
                detInverse = i;
                break;
            }
        }
        
        if (detInverse == -1) {
            throw new IllegalArgumentException("Matriks tidak memiliki invers modulo " + mod);
        }
        
        if (size == 2) {
            return inverse2x2(matrix, detInverse, mod);
        } else {
            return inverse3x3(matrix, detInverse, mod);
        }
    }
    
    // invers matriks 2x2
    private static int[][] inverse2x2(int[][] matrix, int detInverse, int mod) {
        int[][] inverse = new int[2][2];
        inverse[0][0] = Math.floorMod(matrix[1][1] * detInverse, mod);
        inverse[0][1] = Math.floorMod(-matrix[0][1] * detInverse, mod);
        inverse[1][0] = Math.floorMod(-matrix[1][0] * detInverse, mod);
        inverse[1][1] = Math.floorMod(matrix[0][0] * detInverse, mod);
        return inverse;
    }
    
    // invers matriks 3x3
    private static int[][] inverse3x3(int[][] matrix, int detInverse, int mod) {
        int[][] inverse = new int[3][3];
        
        // hitung kofaktor
        int[][] cofactor = new int[3][3];
        cofactor[0][0] = Math.floorMod(matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1], mod);
        cofactor[0][1] = Math.floorMod(-(matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]), mod);
        cofactor[0][2] = Math.floorMod(matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0], mod);
        cofactor[1][0] = Math.floorMod(-(matrix[0][1] * matrix[2][2] - matrix[0][2] * matrix[2][1]), mod);
        cofactor[1][1] = Math.floorMod(matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0], mod);
        cofactor[1][2] = Math.floorMod(-(matrix[0][0] * matrix[2][1] - matrix[0][1] * matrix[2][0]), mod);
        cofactor[2][0] = Math.floorMod(matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1], mod);
        cofactor[2][1] = Math.floorMod(-(matrix[0][0] * matrix[1][2] - matrix[0][2] * matrix[1][0]), mod);
        cofactor[2][2] = Math.floorMod(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0], mod);
        
        // transpose dan kalikan dengan invers determinan
        for (int i = 0; i < 3; i++) {
            for (int j = 0; j < 3; j++) {
                inverse[i][j] = Math.floorMod(cofactor[j][i] * detInverse, mod);
            }
        }
        
        return inverse;
    }
    
    // class untuk simpan hasil enkripsi
    public static class EncryptionResult {
        private final String ciphertext;
        private final List<String> steps;
        
        public EncryptionResult(String ciphertext, List<String> steps) {
            this.ciphertext = ciphertext;
            this.steps = steps;
        }
        
        public String getCiphertext() { return ciphertext; }
        public List<String> getSteps() { return steps; }
    }
    
    // class untuk menyimpan hasil dekripsi dengan detail proses
    public static class DecryptionResult {
        private final String plaintext;
        private final List<String> steps;
        
        public DecryptionResult(String plaintext, List<String> steps) {
            this.plaintext = plaintext;
            this.steps = steps;
        }
        
        public String getPlaintext() { return plaintext; }
        public List<String> getSteps() { return steps; }
    }
}