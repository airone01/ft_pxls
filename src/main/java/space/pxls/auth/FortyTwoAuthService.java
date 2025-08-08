package space.pxls.auth;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;
import kong.unirest.UnirestException;
import kong.unirest.json.JSONObject;
import space.pxls.App;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class FortyTwoAuthService extends AuthService {
    private static final String AUTHORIZATION_URL = "https://api.intra.42.fr/oauth/authorize";
    private static final String TOKEN_URL = "https://api.intra.42.fr/oauth/token";
    private static final String USER_API_URL = "https://api.intra.42.fr/v2/me";

    public FortyTwoAuthService(String id) {
        super(id, App.getConfig().getBoolean("oauth.fortytwo.enabled"),
                App.getConfig().getBoolean("oauth.fortytwo.registrationEnabled"));
    }

    @Override
    public String getRedirectUrl(String state) {
        return AUTHORIZATION_URL +
                "?client_id=" + App.getConfig().getString("oauth.fortytwo.key") +
                "&redirect_uri=" + URLEncoder.encode(App.getConfig().getString("oauth.callbackBase") + "/fortytwo", StandardCharsets.UTF_8) +
                "&response_type=code" +
                "&scope=public" +
                "&state=" + state;
    }

    @Override
    public String getToken(String code) throws UnirestException {
        try {
            HttpResponse<JsonNode> response = Unirest.post(TOKEN_URL)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .field("grant_type", "authorization_code")
                    .field("client_id", App.getConfig().getString("oauth.fortytwo.key"))
                    .field("client_secret", App.getConfig().getString("oauth.fortytwo.secret"))
                    .field("code", code)
                    .field("redirect_uri", App.getConfig().getString("oauth.callbackBase") + "/fortytwo")
                    .asJson();

            if (response.getStatus() != 200) {
                throw new UnirestException("Token exchange failed: " + response.getStatusText());
            }

            return response.getBody().getObject().getString("access_token");
        } catch (UnirestException e) {
            throw new UnirestException("Network error during token exchange", e);
        }
    }

    @Override
    public String getIdentifier(String token) throws UnirestException, InvalidAccountException {
        return getUserData(token).getString("id");
    }

    @Override
    public String getName() { return "fortytwo"; }

    private JSONObject getUserData(String token) throws UnirestException, InvalidAccountException {
        try {
            HttpResponse<JsonNode> response = Unirest.get(USER_API_URL)
                    .header("Authorization", "Bearer " + token)
                    .asJson();

            if (response.getStatus() == 401) {
                throw new InvalidAccountException("Invalid or expired token");
            }

            if (response.getStatus() != 200) {
                throw new UnirestException("Failed to fetch user profile: " + response.getStatusText());
            }

            return response.getBody().getObject();
        } catch (UnirestException e) {
            throw new UnirestException("Network error during profile fetch", e);
        }
    }

    @Override
    public void reloadEnabledState() {
        this.enabled = App.getConfig().getBoolean("oauth.fortytwo.enabled");
        this.registrationEnabled = App.getConfig().getBoolean("oauth.fortytwo.registrationEnabled");
    }
}