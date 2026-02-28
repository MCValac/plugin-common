package io.github.mcvalac.mcbackpack.common;

import io.github.mcvalac.mcbackpack.api.IMCBackpackProvider;
import io.github.mcvalac.mcbackpack.api.db.IMCBackpackDB;
import io.github.mcvalac.mcbackpack.api.model.BackpackData;
import java.util.concurrent.CompletableFuture;

/**
 * Concrete implementation of the {@link IMCBackpackProvider} interface.
 * <p>
 * This class acts as the bridge between the high-level API and the low-level database layer.
 * It delegates all storage operations to the specific {@link IMCBackpackDB} implementation
 * (e.g., MySQL or SQLite) currently in use.
 * </p>
 */
public class MCBackpackProvider implements IMCBackpackProvider {

    /** Static singleton instance for global access. */
    private static MCBackpackProvider instance;

    /** The underlying database implementation used for persistence. */
    private final IMCBackpackDB database;

    /**
     * Constructs the provider with a specific database implementation.
     * <p>
     * Note: This constructor automatically assigns the global singleton instance.
     * It is expected that the main plugin class instantiates this exactly once.
     * </p>
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

    /**
     * Creates a backpack record using the underlying database implementation.
     *
     * @param uuid The unique backpack identifier.
     * @param texture The texture value used to represent the backpack icon.
     * @param size The number of inventory slots to allocate for the backpack.
     * @return A future that completes when the create request has been processed.
     */
    @Override
    public CompletableFuture<Void> create(String uuid, String texture, int size) {
        return database.create(uuid, texture, size);
    }

    /**
     * Opens a backpack record and loads its persisted state.
     *
     * @param uuid The unique backpack identifier.
     * @return A future containing the loaded {@link BackpackData}, or {@code null} if not found.
     */
    @Override
    public CompletableFuture<BackpackData> open(String uuid) {
        return database.open(uuid);
    }

    /**
     * Sets or replaces the password for the specified backpack.
     *
     * @param uuid The unique backpack identifier.
     * @param pwdHash The raw password value to store through the database password pipeline.
     * @return A future that completes once the password is updated.
     */
    @Override
    public CompletableFuture<Void> setPwd(String uuid, String pwdHash) {
        return database.setPwd(uuid, pwdHash);
    }

    /**
     * Verifies whether the provided password matches the stored password for a backpack.
     *
     * @param uuid The unique backpack identifier.
     * @param inputHash The raw password input to verify.
     * @return A future containing {@code true} when the password is valid.
     */
    @Override
    public CompletableFuture<Boolean> checkPwd(String uuid, String inputHash) {
        return database.checkPwd(uuid, inputHash);
    }

    /**
     * Changes the current backpack password to a new raw password.
     *
     * @param uuid The unique backpack identifier.
     * @param newHash The new raw password value.
     * @return A future that completes once the password change is persisted.
     */
    @Override
    public CompletableFuture<Void> changePwd(String uuid, String newHash) {
        return database.changePwd(uuid, newHash);
    }

    /**
     * Deletes the password on a backpack after validating the provided password input.
     *
     * @param uuid The unique backpack identifier.
     * @param inputHash The raw password input used for authorization.
     * @return A future containing {@code true} if the password was removed.
     */
    @Override
    public CompletableFuture<Boolean> deletePwd(String uuid, String inputHash) {
        return database.deletePwd(uuid, inputHash);
    }

    /**
     * Saves backpack inventory contents in serialized Base64 form.
     *
     * @param uuid The unique backpack identifier.
     * @param contentBase64 The serialized inventory payload.
     * @return A future that completes once the content is stored.
     */
    @Override
    public CompletableFuture<Void> save(String uuid, String contentBase64) {
        return database.save(uuid, contentBase64);
    }

    /**
     * Updates the texture value associated with a backpack.
     *
     * @param uuid The unique backpack identifier.
     * @param texture The new texture value to persist.
     * @return A future that completes once the texture is updated.
     */
    @Override
    public CompletableFuture<Void> setTexture(String uuid, String texture) {
        return database.setTexture(uuid, texture);
    }

    /**
     * Closes the provider and releases backing database resources.
     */
    @Override
    public void close() {
        if (database != null) {
            database.close();
        }
        instance = null;
    }
}
