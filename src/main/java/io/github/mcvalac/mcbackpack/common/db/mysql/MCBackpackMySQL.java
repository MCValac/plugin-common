package io.github.mcvalac.mcbackpack.common.db.mysql;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.github.mcvalac.mcbackpack.api.db.IMCBackpackDB;
import io.github.mcvalac.mcbackpack.api.model.BackpackData;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * MySQL implementation of the {@link IMCBackpackDB} interface.
 * <p>
 * This class uses HikariCP for connection pooling and performs asynchronous database operations.
 * It handles the creation, retrieval, and management of backpack data in a MySQL database.
 * </p>
 */
public class MCBackpackMySQL implements IMCBackpackDB {

    private static final String PBKDF2_PREFIX = "pbkdf2$";
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int PBKDF2_KEY_LENGTH = 256;

    /** The connection pool data source. */
    private final HikariDataSource dataSource;

    /**
     * Initializes the MySQL database connection using the provided credentials.
     *
     * @param host     The database host address (e.g., "localhost").
     * @param port     The database port (e.g., "3306").
     * @param database The database name.
     * @param user     The database username.
     * @param password The database password.
     * @param useSsl   Whether to use SSL for the connection.
     */
    public MCBackpackMySQL(String host, String port, String database, String user, String password, boolean useSsl) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://" + host + ":" + port + "/" + database + "?useSSL=" + useSsl);
        config.setUsername(user);
        config.setPassword(password);
        
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(2);
        config.setConnectionTimeout(30000); 
        config.setLeakDetectionThreshold(10000);
        
        config.addDataSourceProperty("cachePrepStmts", "true");
        config.addDataSourceProperty("prepStmtCacheSize", "250");
        config.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");

        this.dataSource = new HikariDataSource(config);

        try {
            createTable();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    /**
     * Creates the necessary tables in the database if they do not already exist.
     *
     * @throws SQLException If a database access error occurs.
     */
    private void createTable() throws SQLException {
        String sql = "CREATE TABLE IF NOT EXISTS mcbackpacks (" +
                "backpack_uuid CHAR(36) NOT NULL PRIMARY KEY, " +
                "texture_value TEXT NOT NULL, " +
                "pwd_hash VARCHAR(255) DEFAULT NULL, " +
                "size INT DEFAULT 27, " +
                "content LONGTEXT, " +
                "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, " +
                "updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP" +
                ");";
        try (Connection conn = dataSource.getConnection(); 
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.execute();
        }
    }

    /**
     * Creates a new backpack row in MySQL with the provided metadata.
     *
     * @param uuid The unique backpack identifier.
     * @param texture The texture value to store for this backpack.
     * @param size The inventory size to persist.
     * @return A future that completes when the insert has finished.
     */
    @Override
    public CompletableFuture<Void> create(String uuid, String texture, int size) {
        return CompletableFuture.runAsync(() -> {
            String insertSql = "INSERT IGNORE INTO mcbackpacks (backpack_uuid, texture_value, size) VALUES (?, ?, ?)";
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement(insertSql)) {
                ps.setString(1, uuid);
                ps.setString(2, texture);
                ps.setInt(3, size);
                ps.executeUpdate();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * Loads a backpack row from MySQL by its unique identifier.
     *
     * @param uuid The unique backpack identifier.
     * @return A future containing the loaded {@link BackpackData}, or {@code null} if not found.
     */
    @Override
    public CompletableFuture<BackpackData> open(String uuid) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = dataSource.getConnection()) {
                try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM mcbackpacks WHERE backpack_uuid = ?")) {
                    ps.setString(1, uuid);
                    ResultSet rs = ps.executeQuery();
                    if (rs.next()) {
                        return new BackpackData(
                                rs.getString("backpack_uuid"),
                                rs.getString("texture_value"),
                                rs.getString("pwd_hash"),
                                rs.getInt("size"),
                                rs.getString("content")
                        );
                    }
                }
                return null;
            } catch (SQLException e) {
                e.printStackTrace();
                return null;
            }
        });
    }

    /**
     * Hashes and stores a password for the target backpack.
     *
     * @param uuid The unique backpack identifier.
     * @param rawPassword The raw password input to hash before persisting.
     * @return A future that completes when the password update is persisted.
     */
    @Override
    public CompletableFuture<Void> setPwd(String uuid, String rawPassword) {
        return CompletableFuture.runAsync(() -> {
            // Generate the salted hash internally
            String saltedHash = generateSaltedHash(rawPassword);
            
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement("UPDATE mcbackpacks SET pwd_hash = ? WHERE backpack_uuid = ?")) {
                ps.setString(1, saltedHash);
                ps.setString(2, uuid);
                ps.executeUpdate();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * Validates a password input against the currently stored hash for a backpack.
     *
     * @param uuid The unique backpack identifier.
     * @param inputRaw The raw password input to verify.
     * @return A future containing {@code true} if the password is valid or not set.
     */
    @Override
    public CompletableFuture<Boolean> checkPwd(String uuid, String inputRaw) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement("SELECT pwd_hash FROM mcbackpacks WHERE backpack_uuid = ?")) {
                ps.setString(1, uuid);
                ResultSet rs = ps.executeQuery();
                if (rs.next()) {
                    String storedHash = rs.getString("pwd_hash");
                    if (storedHash == null) return true;
                    return verifyPassword(inputRaw, storedHash);
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
            return false;
        });
    }

    /**
     * Replaces an existing backpack password with a new raw password.
     *
     * @param uuid The unique backpack identifier.
     * @param newRaw The new raw password value.
     * @return A future that completes when the password replacement is persisted.
     */
    @Override
    public CompletableFuture<Void> changePwd(String uuid, String newRaw) {
        return setPwd(uuid, newRaw); // Reuses setPwd which hashes
    }

    /**
     * Deletes the password for a backpack after optional password verification.
     *
     * @param uuid The unique backpack identifier.
     * @param inputRaw The raw password used for verification, or {@code null} to bypass checks.
     * @return A future containing {@code true} if a password entry was cleared.
     */
    @Override
    public CompletableFuture<Boolean> deletePwd(String uuid, String inputRaw) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = dataSource.getConnection()) {
                try (PreparedStatement check = conn.prepareStatement("SELECT pwd_hash FROM mcbackpacks WHERE backpack_uuid = ?")) {
                    check.setString(1, uuid);
                    ResultSet rs = check.executeQuery();
                    if (rs.next()) {
                        String storedHash = rs.getString("pwd_hash");
                        // If a password exists, require correct input unless caller intentionally bypasses by passing null (ops).
                        if (storedHash != null && inputRaw != null && !verifyPassword(inputRaw, storedHash)) {
                            return false; 
                        }
                    } else {
                        return false; 
                    }
                }
                try (PreparedStatement ps = conn.prepareStatement("UPDATE mcbackpacks SET pwd_hash = NULL WHERE backpack_uuid = ?")) {
                    ps.setString(1, uuid);
                    ps.executeUpdate();
                    return true;
                }
            } catch (SQLException e) {
                e.printStackTrace();
                return false;
            }
        });
    }

    /**
     * Persists serialized inventory content for a backpack.
     *
     * @param uuid The unique backpack identifier.
     * @param contentBase64 The serialized Base64 inventory payload.
     * @return A future that completes when the content update is persisted.
     */
    @Override
    public CompletableFuture<Void> save(String uuid, String contentBase64) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement("UPDATE mcbackpacks SET content = ? WHERE backpack_uuid = ?")) {
                ps.setString(1, contentBase64);
                ps.setString(2, uuid);
                ps.executeUpdate();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * Updates the texture value associated with a backpack.
     *
     * @param uuid The unique backpack identifier.
     * @param texture The new texture value to store.
     * @return A future that completes when the texture update is persisted.
     */
    @Override
    public CompletableFuture<Void> setTexture(String uuid, String texture) {
        return CompletableFuture.runAsync(() -> {
            try (Connection conn = dataSource.getConnection();
                 PreparedStatement ps = conn.prepareStatement("UPDATE mcbackpacks SET texture_value = ? WHERE backpack_uuid = ?")) {
                ps.setString(1, texture);
                ps.setString(2, uuid);
                ps.executeUpdate();
            } catch (SQLException e) {
                e.printStackTrace();
            }
        });
    }

    /**
     * Closes the MySQL connection pool if it is still open.
     */
    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
        }
    }

    /**
     * Generates a salted SHA-256 hash for the given password.
     *
     * @param password The raw password to hash.
     * @return A string in the format {@code salt$hash}.
     */
    private String generateSaltedHash(String password) {
        try {
            byte[] salt = new byte[16];
            new SecureRandom().nextBytes(salt);

            KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();

            return PBKDF2_PREFIX + PBKDF2_ITERATIONS + "$" +
                    Base64.getEncoder().encodeToString(salt) + "$" +
                    Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to hash password", e);
        }
    }

    /**
     * Verifies if a raw input matches a stored salted hash.
     *
     * @param inputRaw   The raw input password to check.
     * @param storedHash The stored string containing the salt and hash ({@code salt$hash}).
     * @return {@code true} if the input matches the hash, {@code false} otherwise.
     */
    private boolean verifyPassword(String inputRaw, String storedHash) {
        try {
            if (storedHash.startsWith(PBKDF2_PREFIX)) {
                String[] parts = storedHash.split("\\$");
                if (parts.length != 4) return false;
                int iterations = Integer.parseInt(parts[1]);
                byte[] salt = Base64.getDecoder().decode(parts[2]);
                byte[] expected = Base64.getDecoder().decode(parts[3]);

                KeySpec spec = new PBEKeySpec(inputRaw.toCharArray(), salt, iterations, PBKDF2_KEY_LENGTH);
                SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                byte[] actual = skf.generateSecret(spec).getEncoded();
                return MessageDigest.isEqual(actual, expected);
            }

            if (!storedHash.contains("$")) return false;
            String[] parts = storedHash.split("\\$");
            if (parts.length != 2) return false;
            String salt = parts[0];
            String expectedHex = parts[1];

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] actual = digest.digest((salt + inputRaw).getBytes(StandardCharsets.UTF_8));
            byte[] expected = hexToBytes(expectedHex);
            return expected != null && MessageDigest.isEqual(actual, expected);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Converts a hexadecimal string into its byte-array representation.
     *
     * @param hex The hexadecimal string to decode.
     * @return The decoded bytes, or {@code null} when input format is invalid.
     */
    private byte[] hexToBytes(String hex) {
        if (hex.length() % 2 != 0) return null;
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high < 0 || low < 0) return null;
            bytes[i / 2] = (byte) ((high << 4) + low);
        }
        return bytes;
    }
}
