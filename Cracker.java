import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.function.BiConsumer;
import java.util.function.Predicate;

import static java.nio.file.StandardOpenOption.*;

public class Cracker {

    private static Path inputFile, outputFile, rulesFile, errorFile;
    private static Map<String, String> uncracked;
    private static MessageDigest hashFunction;
    private static List<Pipeline> pipeline;

    public static void main(String[] args) {
        // check if we need to do generation mode instead
        if (args.length > 0) {
            switch (args[0]) {
                case "filter": handleFilterMode(args); return;
                case "replace": handleSubstituteMode(args); return;
            }
        }

        // set the default values for shell arguments
        String inputPath = "input.txt";
        String outputPath = "output.txt";
        String rulesPath = "rules.conf";
        String errorPath = "error.log";
        String algorithm = "SHA-256";

        // read the key-value argument pairs
        for (String arg : args) {
            String[] parts = arg.split("=");
            switch (parts[0]) {
                case "in":    inputPath = parts[1]; break;
                case "out":   outputPath = parts[1]; break;
                case "rules": rulesPath = parts[1]; break;
                case "error": errorPath = parts[1]; break;
                case "alg":   algorithm = parts[1]; break;
                default: throw new IllegalArgumentException("No such argument '" + parts[0] + "'");
            }
        }

        // make sure all the necessary files exist
        inputFile = resolveFile(inputPath, true);
        outputFile = resolveFile(outputPath, false);
        rulesFile = resolveFile(rulesPath, true);
        errorFile = resolveFile(errorPath, false);

        hashFunction = getHashFunction(algorithm);
        uncracked = getHashes();
        int initialPassCount = uncracked.size();

        System.out.println("Beginning now...");

        // iterate through the rules in the rules file
        for (String rule : getRules(rulesFile)) {

            // skip empty lines and comments
            if (rule.trim().isEmpty() || rule.trim().startsWith("#")) {
                continue;
            }

            String[] commands = rule.split("\\|");

            // the generator is the first command in a pipeline
            Runnable generator = getGeneratorCommand(commands[0].trim());

            // and now parse the remaining commands on this line, if any
            pipeline = new ArrayList<>();
            for (int i = 1; i < commands.length; i++) {
                pipeline.add(getPipelineCommand(commands[i].trim()));
            }

            // the last, implicit command is to compare passwords to the input file
            pipeline.add(Cracker::checkHash);

            // begin executing the rule on this line
            generator.run();
        }

        // if we get here, that means we weren't able to crack every password
        int numCracked = initialPassCount - uncracked.size();
        System.out.println("Cracked " + numCracked + " / " + initialPassCount + " passwords.");
        System.out.println("Uncracked:");
        displayUnsolved();
    }

    /**
     * Ensure a file exists and is not a directory. If it's usable, return it.
     * @param path the file path to check
     * @param mustExist whether the file needs to exist already
     * @return a path object pointing to the file
     */
    private static Path resolveFile(String path, boolean mustExist) {
        if (mustExist && Files.notExists(Paths.get(path))) {
            System.out.println("Cannot find file: " + path);
            System.exit(1);
        } else if (Files.isDirectory(Paths.get(path))) {
            System.out.println("File cannot be directory: " + path);
            System.exit(1);
        }
        return Paths.get(path);
    }

    /**
     * Retrieve the desired hashing function if it exists on this system.
     * @param algorithm the algorithm name, such as "SHA-256"
     * @return a message digest object that provides the algorithm
     */
    private static MessageDigest getHashFunction(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            System.out.println("Unknown algorithm '" + algorithm + "'");
            System.exit(1);
            return null;
        }
    }

    /**
     * Retrieve the hashed passwords from the input file.
     * @return a map of hash:username pairs
     */
    private static Map<String, String> getHashes() {
        try {
            Scanner scanner = new Scanner(inputFile);
            Map<String, String> input = new HashMap<>();
            while (scanner.hasNextLine()) {
                String[] parts = scanner.nextLine().split(":");
                if (parts.length < 2) {
                    logErrorAndQuit("Malformed line in input file: " + parts[0]);
                }
                input.put(parts[1], parts[0]);
            }
            return input;
        } catch (IOException e) {
            logErrorAndQuit("Couldn't read from input file: " + e.getLocalizedMessage());
            return Collections.emptyMap(); // dummy return to make the compiler happy
        }
    }

    /**
     * Retrieve a list of rules from the rules file.
     * @param rulesFile the rules file
     * @return a list of rules as unparsed strings
     */
    private static List<String> getRules(Path rulesFile) {
        try {
            return Files.readAllLines(rulesFile);
        } catch (IOException e) {
            logErrorAndQuit("Couldn't read from rules file: " + e.getLocalizedMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Parse a generator command, the first command in a rule, defined in
     * the rules file.
     * @param command the command to parse
     * @return an executable that will generate passwords guesses
     */
    private static Runnable getGeneratorCommand(String command) {
        if (command.matches("read \".*\"")) {
            String fileName = command.substring(6, command.length() - 1);
            return () -> {
                try {
                    BufferedReader reader = new BufferedReader(new FileReader(fileName));
                    String word;
                    while ((word = reader.readLine()) != null) {
                        pipeline.get(0).accept(word, 0);
                    }
                    reader.close();
                } catch (IOException e) {
                    logErrorAndQuit("Couldn't read from word file: " + e.getLocalizedMessage());
                }
            };
        } else if (command.matches("permute \".*\"")) {
            String choices = command.substring(9, command.length() - 1);
            return () -> {
                for (String permutation : permute(choices)) {
                    pipeline.get(0).accept(permutation, 0);
                }
            };
        } else if (command.matches("\\d+ to \\d+ digits?")) {
            String[] parts = command.split(" ");
            int minDigits = Integer.parseInt(parts[0]);
            int maxDigits = Integer.parseInt(parts[2]);
            return () -> {
                for (int digits = minDigits; digits <= maxDigits; digits++) {
                    int maxValue = (int) Math.pow(10, digits);
                    for (int n = 0; n < maxValue; n++) {
                        pipeline.get(0).accept(zeroPadded(n, digits), 0);
                    }
                }
            };
        }
        throw new IllegalArgumentException("Unknown rule '" + command + "'");
    }

    /**
     * Parse a non-generator command defined in the rules file.
     * @param command the command to parse
     * @return an executable that accepts a password and outputs variants
     *         of that password
     */
    private static Pipeline getPipelineCommand(String command) {
        if (command.equals("add capitalized")) {
            return (word, index) -> {
                pipeline.get(index + 1).accept(word, index + 1);
                pipeline.get(index + 1).accept(capitalize(word), index + 1);
            };
        } else if (command.matches("add \\d+ digits?")) {
            int count = Integer.parseInt(command.split(" ")[1]);
            int max = (int) Math.pow(10, count);
            return (word, index) -> {
                Pipeline nextFunction = pipeline.get(index + 1);
                for (int i = 0; i < max; i++) {
                    nextFunction.accept(word + zeroPadded(i, count), index + 1);
                }
            };
        }
        throw new IllegalArgumentException("Unknown rule '" + command + "'");
    }

    /**
     * Zero-pad a number to the specified length.
     * @param num the number to pad
     * @param length the desired length of the result
     * @return the zero-padded number
     */
    private static String zeroPadded(int num, int length) {
        return String.format("%0" + length + "d", num);
    }

    /**
     * Capitalize a word.
     * @param word the word to capitalize
     * @return the capitalized word
     */
    private static String capitalize(String word) {
        return word.substring(0, 1).toUpperCase() + word.substring(1);
    }

    /**
     * Compute the permutations of an input string, including permutations
     * smaller than the input string.
     * @param str the characters to permute
     * @return a set containing the permutations
     */
    private static Set<String> permute(String str) {
        if (str.isEmpty()) {
            return new HashSet<>(Collections.singletonList(""));
        }
        Set<String> results = permute(str.substring(1));
        for (String partial : results.toArray(new String[0])) {
            for (int i = 0; i <= partial.length(); i++){
                results.add(partial.substring(0, i) + str.charAt(0) + partial.substring(i));
            }
        }
        return results;
    }

    /**
     * Check if a particular word matches one of the remaining hashes.
     * If it does, output it and remove it from the map.
     * @param word the password to check
     * @param ignore a dummy parameter to match the functional interface signature
     */
    private static void checkHash(String word, int ignore) {
        String hashed = hash(word.getBytes(), hashFunction);
        if (uncracked.containsKey(hashed)) {
            String solvedPair = uncracked.get(hashed) + " : " + word;
            System.out.println("Cracked " + solvedPair);
            uncracked.remove(hashed);
            try {
                // try to write to the output file
                Files.write(outputFile, (solvedPair + "\n").getBytes(), APPEND, CREATE);
            } catch (IOException e) {
                logError("Couldn't write to output file: " + e.getLocalizedMessage());
            }

            // check if there are any remaining passwords
            if (uncracked.isEmpty()) {
                System.out.println("All passwords cracked.");
                System.exit(0);
            }
        }
    }

    /**
     * Print out the remaining unsolved user:hash pairs.
     */
    private static void displayUnsolved() {
        final int MAX_TO_SHOW = 6;
        int shown = 0;
        for (Map.Entry<String, String> pair : uncracked.entrySet()) {
            System.out.println("  " + pair.getValue() + " : " + pair.getKey());
            if (++shown >= MAX_TO_SHOW) {
                System.out.println("  And " + (uncracked.size() - MAX_TO_SHOW) + " more...");
                break;
            }
        }
    }

    /**
     * Handle the generator tool's filter mode.
     * @param args the command line arguments
     */
    private static void handleFilterMode(String[] args) {
        if (args.length < 2) {
            System.out.println("Missing filter arguments. See readme for usage.");
            System.exit(1);
        }

        Path pathToRead = resolveFile(args[1], true);
        int length = -1;
        String contains = "";

        for (int i = 2; i < args.length; i++) {
            String[] parts = args[i].split("=");
            switch (parts[0]) {
                case "len": length = Integer.parseInt(parts[1]); break;
                case "has": contains = parts[1]; break;
                default: throw new IllegalArgumentException("No such argument '" + parts[0] + "'");
            }
        }

        int tempLength = length;
        String tempContains = contains;
        Predicate<String> predicate;

        if (length == -1 && contains.isEmpty()) {
            predicate = word -> true;
        } else if (length == -1) {
            predicate = word -> anyInString(word, tempContains);
        } else if (contains.isEmpty()) {
            predicate = word -> word.length() == tempLength;
        } else {
            predicate = word -> word.length() == tempLength && anyInString(word, tempContains);
        }

        try {
            BufferedReader reader = new BufferedReader(new FileReader(pathToRead.toFile()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (predicate.test(line)) {
                    System.out.println(line);
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("Couldn't find input file: " + args[1]);
            System.exit(1);
        } catch (IOException e) {
            logErrorAndQuit("Failed to read the input file: " + e.getLocalizedMessage());
        }
    }

    /**
     * Check if any characters in one string appear in another.
     * @param word the word to search through
     * @param queries the characters to search for
     * @return true if any characters were found; false otherwise
     */
    private static boolean anyInString(String word, String queries) {
        for (char c : queries.toCharArray()) {
            if (word.indexOf(c) >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Handle the generator tool's replace mode.
     * @param args the command line arguments
     */
    private static void handleSubstituteMode(String[] args) {
        if (args.length < 3) {
            System.out.println("Missing substitution arguments. See readme for usage.");
            System.exit(1);
        }
        String inputPath = args[1];
        Map<Character, Character> replace = new HashMap<>();
        for (int i = 2; i < args.length; i++) {
            if (args[i].length() != 2) {
                System.out.println("Malformed substitution argument: " + args[i]);
                System.exit(1);
            }
            replace.put(args[i].charAt(0), args[i].charAt(1));
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(inputPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                for (List<Integer> indices : computeIndexPowerSet(line.trim(), replace.keySet())) {
                    String word = line.trim();
                    for (int index : indices) {
                        word = word.substring(0, index) + replace.get(word.charAt(index)) + word.substring(index + 1);
                    }
                    System.out.println(word);
                }
            }
        } catch (IOException e) {
            logErrorAndQuit("Couldn't read or write during substitution: " + e.getLocalizedMessage());
        }
    }

    /**
     * Compute the power set (the set of all subsets) of certain characters in a
     * word, excluding the empty set. For example, for the word 'balrog', the output
     * would be {'a', 'l', 'al'} except containing the character's indices, rather than
     * the characters themselves.
     * @param word the word to search through
     * @param chars the character to search for
     * @return the power set of the indices of characters in the word
     */
    private static Set<List<Integer>> computeIndexPowerSet(String word, Set<Character> chars) {
        List<Integer> indices = new ArrayList<>();
        for (int i = 0; i < word.length(); i++) {
            if (chars.contains(word.charAt(i))) {
                indices.add(i);
            }
        }
        final int SIZE = indices.size();
        Set<List<Integer>> powerSet = new HashSet<>();
        List<Integer> current = new ArrayList<>();
        for (int i = 1; i < 2 << SIZE - 1; i++) {       // (2 << SIZE - 1) is a faster 2**SIZE
            for (int j = 0; j < SIZE; j++) {
                if ((i & 1 << j) > 0) {                 // (i & 1 << j) isolates bit j
                    current.add(indices.get(j));
                }
            }
            powerSet.add(current);
            current = new ArrayList<>();
        }
        return powerSet;
    }

    /**
     * Log an error message and exit the program.
     * @param message the message to log
     */
    private static void logErrorAndQuit(String message) {
        logError(message);
        System.exit(1);
    }

    /**
     * Log an error message.
     * @param message the message to log
     */
    private static void logError(String message) {
        try {
            String timestamp = LocalDateTime.now().toString();
            Files.write(errorFile, (timestamp + " " + message + "\n").getBytes(), APPEND, CREATE);
            System.out.println(message);
        } catch (IOException e) {
            System.out.println("An error occurred while writing to the error log.");
            System.out.println("The original error was:");
            System.err.println(message);
            System.out.println("The error that prohibited writing to the log was:");
            e.printStackTrace();
        }
        System.exit(1);
    }

    /**
     * Apply the hashing function to a sequence of bytes.
     * @param message the bytes to hash
     * @param function the hashing function
     * @return the hashed message in hexadecimal
     */
    private static String hash(byte[] message, MessageDigest function) {
        return bytesToHex(function.digest(message));
    }

    /**
     * Convert a sequence of bytes to a hexadecimal string.
     * @param bytes the bytes to convert
     * @return a hexadecimal string
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder output = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                output.append('0');
            }
            output.append(hex);
        }
        return output.toString();
    }

    /**
     * A convenience interface so we can write Pipeline instead
     * of BiConsumer<String, Integer>.
     */
    private interface Pipeline extends BiConsumer<String, Integer> {}

}
