package cncs.academy.ess.controller;

import cncs.academy.ess.controller.messages.ErrorMessage;
import cncs.academy.ess.controller.messages.UserAddRequest;
import cncs.academy.ess.controller.messages.UserLoginRequest;
import cncs.academy.ess.controller.messages.UserResponse;
import cncs.academy.ess.model.User;
import cncs.academy.ess.service.TodoUserService;
import io.javalin.http.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class UserController {

    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final TodoUserService userService;

    public UserController(TodoUserService userService) {
        this.userService = userService;
    }

    public void createUser(Context ctx) throws Exception {
        UserAddRequest userRequest = ctx.bodyAsClass(UserAddRequest.class);
        log.info("Create user: {}", userRequest.username);
        byte[] salt = generateSalt();
        log.info("User Salt: {}", bytesToHex(salt));

        User user = userService.addUser(userRequest.username, getHashedPassword(userRequest.password, salt), bytesToHex(salt));
        UserResponse response = new UserResponse(user.getId(), user.getUsername());
        ctx.status(201).json(response);
    }

    public void getUser(Context ctx) {
        int userId = Integer.parseInt(ctx.pathParam("userId"));
        User user = userService.getUser(userId);
        if (user != null) {
            UserResponse response = new UserResponse(user.getId(), user.getUsername());
            ctx.status(200).json(response);
        } else {
            ctx.status(404).json(new ErrorMessage("User not found"));
        }
    }

    public void deleteUser(Context ctx) {
        int userId = Integer.parseInt(ctx.pathParam("userId"));
        userService.deleteUser(userId);
        ctx.status(204);
    }

    public void loginUser(Context ctx) throws Exception {
        UserLoginRequest userRequest = ctx.bodyAsClass(UserLoginRequest.class);
        log.info("Login user: {}", userRequest.username);
        String token = userService.login(userRequest.username, userRequest.password);
        if (token != null) {
            ctx.status(200).json(token);
        } else {
            ctx.status(401).json(new ErrorMessage("Invalid username or password"));
        }
    }

    private static String getHashedPassword(String password, byte[] salt) throws Exception {
        // Hash the password using PBKDF2
        byte[] hashedPassword = hashPassword(password, salt, 10000, 256);

        // Convert the hashed password to a string for storage
        return bytesToHex(hashedPassword);
    }

    private static byte[] hashPassword(String password, byte[] salt, int iterations, int keyLength) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    public static byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16]; // 16 bytes for the salt
        random.nextBytes(salt);
        return salt;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static boolean validatePassword(String password, byte[] salt, byte[] storedHash, int iterations, int keyLength) throws Exception {
        byte[] hashToCheck = hashPassword(password, salt, iterations, keyLength);
        return Arrays.equals(hashToCheck, storedHash);
    }
}

    public void addProfilePicture(Context ctx) {
        String userId = ctx.pathParam("userId");
        String destinationDir = "/app/profiles/" + userId;
        try {
            java.io.InputStream zipInput = ctx.uploadedFile("profileZip").content();
            java.util.zip.ZipInputStream zis = new java.util.zip.ZipInputStream(zipInput);
            java.util.zip.ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                // Vulnerability: Directly using zip entry name without validation
                java.io.File profilePic = new java.io.File(destinationDir, entry.getName());
                // Blindly create directories
                profilePic.getParentFile().mkdirs();
                // Extract the file without path validation
                java.nio.file.Files.copy(zis, profilePic.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
            ctx.status(200).json("Profile pictures uploaded successfully");
        } catch (Exception e) {
            ctx.status(500).result("Error uploading profile pictures");
        }
    }
}
