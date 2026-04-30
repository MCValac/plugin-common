package io.github.mcvalac.mcbackpack.common.db.api;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.github.mcvalac.mcbackpack.api.db.IMCBackpackDB;
import io.github.mcvalac.mcbackpack.api.model.BackpackData;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

/**
 * HTTP POST-backed remote API implementation of the IMCBackpackDB interface.
 */
public class MCBackpackAPI implements IMCBackpackDB {

    private static final String ENV_URL = "MCSERVER_URL";
    private static final String ENV_TOKEN = "MCSERVER_API_TOKEN";
    
    // Fallback UUID for administrative API calls that lack a specific player context
    private static final String SYSTEM_UUID = "00000000-0000-0000-0000-000000000000";

    private final String apiUrl;
    private final String apiToken;
    private final HttpClient httpClient;
    private final Gson gson;

    public MCBackpackAPI() {
        this.apiUrl = System.getenv(ENV_URL);
        this.apiToken = System.getenv(ENV_TOKEN);
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        this.gson = new Gson();

        if (this.apiUrl == null || this.apiToken == null) {
            System.err.println("[MCBackpack API] Missing environment variables: " + ENV_URL + " or " + ENV_TOKEN);
        }
    }

    private CompletableFuture<JsonObject> sendRequest(JsonObject payload) {
        if (this.apiUrl == null || this.apiToken == null) {
            return CompletableFuture.completedFuture(new JsonObject());
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(this.apiUrl + "/api/backpack"))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + this.apiToken)
                .POST(HttpRequest.BodyPublishers.ofString(gson.toJson(payload)))
                .build();

        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        return JsonParser.parseString(response.body()).getAsJsonObject();
                    } else {
                        System.err.println("[MCBackpack API] Request failed with status code: " + response.statusCode() + " Body: " + response.body());
                        return new JsonObject();
                    }
                })
                .exceptionally(ex -> {
                    System.err.println("[MCBackpack API] Request exception: " + ex.getMessage());
                    return new JsonObject();
                });
    }

    @Override
    public CompletableFuture<Void> create(String uuid, String texture, int size) {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", "create");
        payload.addProperty("uuid", uuid);
        payload.addProperty("player_uuid", SYSTEM_UUID); // Required by express router tracking
        payload.addProperty("texture", texture);
        payload.addProperty("size", size);
        return sendRequest(payload).thenAccept(r -> {});
    }

    @Override
    public CompletableFuture<BackpackData> open(String uuid, String playerUuid) {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", "get");
        payload.addProperty("uuid", uuid);
        payload.addProperty("player_uuid", playerUuid); // Use actual player UUID for locks

        return sendRequest(payload).thenApply(r -> {
            if (r.has("uuid")) {
                return new BackpackData(
                        r.get("uuid").getAsString(),
                        r.has("texture_value") && !r.get("texture_value").isJsonNull() ? r.get("texture_value").getAsString() : "",
                        null, // Never send raw hash back to the client for security
                        r.has("size") && !r.get("size").isJsonNull() ? r.get("size").getAsInt() : 27,
                        r.has("contents") && !r.get("contents").isJsonNull() ? r.get("contents").getAsString() : null
                );
            }
            return null;
        });
    }

    @Override
    public CompletableFuture<Void> setPwd(String uuid, String rawPassword) {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", "set_pwd");
        payload.addProperty("uuid", uuid);
        payload.addProperty("player_uuid", SYSTEM_UUID); // Required by express router tracking
        payload.addProperty("raw_password", rawPassword);
        return sendRequest(payload).thenAccept(r -> {});
    }

    @Override
    public CompletableFuture<Boolean> checkPwd(String uuid, String inputRaw) {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", "check_pwd");
        payload.addProperty("uuid", uuid);
        payload.addProperty("player_uuid", SYSTEM_UUID); // Required by express router tracking
        payload.addProperty("raw_password", inputRaw);
        return sendRequest(payload).thenApply(r -> r.has("valid") && r.get("valid").getAsBoolean());
    }

    @Override
    public CompletableFuture<Void> changePwd(String uuid, String newRaw) {
        return setPwd(uuid, newRaw);
    }

    @Override
    public CompletableFuture<Boolean> deletePwd(String uuid, String inputRaw) {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", "delete_pwd");
        payload.addProperty("uuid", uuid);
        payload.addProperty("player_uuid", SYSTEM_UUID); // Required by express router tracking
        if (inputRaw != null) {
            payload.addProperty("raw_password", inputRaw);
        } else {
            payload.addProperty("force", true);
        }
        return sendRequest(payload).thenApply(r -> r.has("success") && r.get("success").getAsBoolean());
    }

    @Override
    public CompletableFuture<Void> save(String uuid, String contentBase64, String playerUuid) {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", "save");
        payload.addProperty("uuid", uuid);
        payload.addProperty("player_uuid", playerUuid); // Unlock requires the exact player UUID
        payload.addProperty("contents", contentBase64);
        return sendRequest(payload).thenAccept(r -> {});
    }

    @Override
    public CompletableFuture<Void> setTexture(String uuid, String texture) {
        JsonObject payload = new JsonObject();
        payload.addProperty("action", "set_texture");
        payload.addProperty("uuid", uuid);
        payload.addProperty("player_uuid", SYSTEM_UUID); // Required by express router tracking
        payload.addProperty("texture", texture);
        return sendRequest(payload).thenAccept(r -> {});
    }

    @Override
    public void close() {
        // HttpClient handles resources inherently
    }
}
