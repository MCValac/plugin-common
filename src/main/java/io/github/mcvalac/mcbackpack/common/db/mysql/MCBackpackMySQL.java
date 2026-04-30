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

    @Override
    public CompletableFuture<BackpackData> open(String uuid, String playerUuid) {
        // MySQL implementation does not currently use player tracking, redirect to base
        return open(uuid);
    }

    @Override
    public CompletableFuture<Void> setPwd(String uuid, String rawPassword) {
        return CompletableFuture.runAsync(() -> {
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

    @Override
    public CompletableFuture<Void> changePwd(String uuid, String newRaw) {
        return setPwd(uuid, newRaw);
    }

    @Override
    public CompletableFuture<Boolean> deletePwd(String uuid, String inputRaw) {
        return CompletableFuture.supplyAsync(() -> {
            try (Connection conn = dataSource.getConnection()) {
                try (PreparedStatement check = conn.prepareStatement("SELECT pwd_hash FROM mcbackpacks WHERE backpack_uuid = ?")) {
                    check.setString(1, uuid);
                    ResultSet rs = check.executeQuery();
                    if (rs.next()) {
                        String storedHash = rs.getString("pwd_hash");
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

    @Override
    public CompletableFuture<Void> save(String uuid, String contentBase64, String playerUuid) {
        // MySQL implementation does not currently use player tracking, redirect to base
        return save(uuid, contentBase64);
    }

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

    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
        }
    }

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
