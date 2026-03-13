package cncs.academy.ess.service;

import cncs.academy.ess.model.User;
import cncs.academy.ess.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneId;
import static cncs.academy.ess.controller.UserController.validatePassword;
import static cncs.academy.ess.helpers.Jwt.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

public class TodoUserService {
    private final UserRepository repository;

    public TodoUserService(UserRepository userRepository) {
        this.repository = userRepository;
    }
    public User addUser(String username, String password, String salt) throws NoSuchAlgorithmException {
        User user = new User(username, password, salt);
        int id = repository.save(user);
        user.setId(id);
        return user;
    }
    public User getUser(int id) {
        return repository.findById(id);
    }

    public void deleteUser(int id) {
        repository.deleteById(id);
    }

    public String login(String username, String password) throws Exception {
        User user = repository.findByUsername(username);
        if (user == null) {
            return null;
        }
        if (validatePassword(password, hexStringToByteArray(user.getSalt()), hexStringToByteArray(user.getPassword()), 10000, 256)) {
            return createAuthToken(user);
        }
        return null;
    }

    private String createAuthToken(User user) {
       // return "Bearer " + user.getUsername();

        try {
            Algorithm algorithm = getAlgorith(false);
            Date now = new Date();

            String token = JWT.create()
                    .withIssuer("grupo_9")
                    .withExpiresAt(Date.from(
                            now.toInstant()
                                    .atZone(ZoneId.systemDefault())
                                    .toLocalDateTime()
                                    .plusDays(1)
                                    .atZone(ZoneId.systemDefault())
                                    .toInstant()
                    ))
                    .withIssuedAt(new Date())
                    .withClaim("username", user.getUsername())
                    .withSubject("grupo_9")
                    .sign(algorithm);
            return token;
        } catch (JWTCreationException exception){
            // Invalid Signing configuration / Couldn't convert Claims.
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return "";
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }



}
