package io.github.mcvalac.mcbackpack.common;

import io.github.mcvalac.mcbackpack.api.IMCBackpackProvider;
import io.github.mcvalac.mcbackpack.api.db.IMCBackpackDB;
import io.github.mcvalac.mcbackpack.api.model.BackpackData;
import java.util.concurrent.CompletableFuture;

/**
 * Concrete implementation of the {@link IMCBackpackProvider} interface.
 * <p>
 * This class acts as the bridge between the high-level API and the low-level database layer.
 * It delegates all storage operations to the specific {@link IMCBackpackDB} implementation.
 * </p>
 */
public class MCBackpackProvider implements IMCBackpackProvider {

    /** Static singleton instance for global access. */
    private static MCBackpackProvider instance;

    /** The underlying database implementation used for persistence. */
    private final IMCBackpackDB database;

    /**
     * Constructs the provider with a specific database implementation.
     *
     * @param database The database instance to use.
     */
    public MCBackpackProvider(IMCBackpackDB database) {
        this.database = database;
        instance = this; // Assign singleton
    }

    /**
     * Retrieves the singleton instance of the provider.
     *
     * @return The active provider instance, or {@code null} if not initialized yet.
     */
    public static MCBackpackProvider getProvider() {
        return instance;
    }

    @Override
    public CompletableFuture<Void> create(String uuid, String texture, int size) {
        return database.create(uuid, texture, size);
    }

    /**
     * Opens a backpack record and loads its persisted state.
     * * @param uuid The unique backpack identifier.
     * @param playerUuid The UUID of the player opening the backpack (used for locks and logs).
     * @return A future containing the loaded {@link BackpackData}, or {@code null} if not found.
     */
    @Override
    public CompletableFuture<BackpackData> open(String uuid, String playerUuid) {
        return database.open(uuid, playerUuid);
    }

    @Override
    public CompletableFuture<Void> setPwd(String uuid, String pwdHash) {
        return database.setPwd(uuid, pwdHash);
    }

    @Override
    public CompletableFuture<Boolean> checkPwd(String uuid, String inputHash) {
        return database.checkPwd(uuid, inputHash);
    }

    @Override
    public CompletableFuture<Void> changePwd(String uuid, String newHash) {
        return database.changePwd(uuid, newHash);
    }

    @Override
    public CompletableFuture<Boolean> deletePwd(String uuid, String inputHash) {
        return database.deletePwd(uuid, inputHash);
    }

    /**
     * Saves backpack inventory contents in serialized Base64 form.
     *
     * @param uuid The unique backpack identifier.
     * @param contentBase64 The serialized inventory payload.
     * @param playerUuid The UUID of the player saving the backpack (used to unlock).
     * @return A future that completes once the content is stored.
     */
    @Override
    public CompletableFuture<Void> save(String uuid, String contentBase64, String playerUuid) {
        return database.save(uuid, contentBase64, playerUuid);
    }

    @Override
    public CompletableFuture<Void> setTexture(String uuid, String texture) {
        return database.setTexture(uuid, texture);
    }

    @Override
    public void close() {
        if (database != null) {
            database.close();
        }
        instance = null;
    }
}
