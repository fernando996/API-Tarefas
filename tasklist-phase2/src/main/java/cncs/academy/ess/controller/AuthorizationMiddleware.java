package cncs.academy.ess.controller;

import cncs.academy.ess.model.User;
import cncs.academy.ess.repository.UserRepository;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.javalin.http.*;
import org.casbin.jcasbin.main.Enforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static cncs.academy.ess.helpers.Jwt.getAlgorith;
import static cncs.academy.ess.helpers.Jwt.loadPublicKey;

public class AuthorizationMiddleware implements Handler {
    private static final Logger logger = LoggerFactory.getLogger(AuthorizationMiddleware.class);
    private final UserRepository userRepository;

    public AuthorizationMiddleware(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public void handle(Context ctx) throws Exception {
        // if method is OPTIONS bypass auth middleware
        if (ctx.method() == HandlerType.OPTIONS) {
            // Optionally: validate if it is a legitimate CORS preflight
            return;
        }

        // Allow unauthenticated requests to /user (register) and /login
        if (ctx.path().equals("/user") && ctx.method().name().equals("POST") ||
                ctx.path().equals("/login") && ctx.method().name().equals("POST"))
            return;

        // Check if authorization header exists
        String authorizationHeader = ctx.header("Authorization");
        String path = ctx.path();
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            logger.info("Authorization header is missing or invalid '{}' for path '{}'", authorizationHeader, path);
            throw new UnauthorizedResponse();
        }

        // Extract token from authorization header
        String token = authorizationHeader.substring(7); // Remove "Bearer "

        // Check if token is valid (perform authentication logic)
        int userId = validateTokenAndGetUserId(token, ctx);
        if (userId == -1) {
            logger.info("Authorization token is invalid {}", token);
            throw new UnauthorizedResponse();
        } else if (userId == -2) {
            logger.info("Authorization permissions are not valid");
            throw new ForbiddenResponse();
        }

        // Add user ID to context for use in route handlers
        ctx.attribute("userId", userId);
    }

    /**
     * NOTE: This method currently uses username lookup as a placeholder for real token validation.
     * Replace with proper token parsing/verification (e.g., JWT, session lookup) as needed.
     */
    private Integer validateTokenAndGetUserId(String token, Context ctx) {

        DecodedJWT decodedJWT;
        try {
            Algorithm algorithm = getAlgorith(true);

            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer("grupo_9")
                    .build();


            decodedJWT = verifier.verify(token);

            // Placeholder behavior: treat token as username (legacy behavior)
            User user = userRepository.findByUsername(decodedJWT.getClaim("username").asString());

            if (user == null) {
                return -1;
            }

            Enforcer enforcer = new Enforcer("./api-access-control/model.conf", "./api-access-control/policy.csv");

            if (!(enforcer.enforce(user.getUsername(), ctx.path(), ctx.method().name()) == true)) {
                return -2;
            }

            return user.getId();

        } catch (JWTVerificationException exception) {
            // Invalid signature/claims
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return -1;

    }
}

