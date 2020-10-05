// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fido.iot.storage;

import java.security.PublicKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.UUID;
import javax.sql.DataSource;
import org.fido.iot.protocol.Composite;
import org.fido.iot.protocol.Const;
import org.fido.iot.protocol.CryptoService;
import org.fido.iot.protocol.InvalidJwtException;
import org.fido.iot.protocol.ResourceNotFoundException;
import org.fido.iot.protocol.To0ServerStorage;

/**
 * Database Storage implementation.
 */
public class To0DbStorage implements To0ServerStorage {

  private final CryptoService cryptoService;
  private final DataSource dataSource;
  private byte[] nonce3;

  /**
   * Constructs a To0DbStorage instance.
   *
   * @param cryptoService A crypto Service.
   * @param dataSource    A SQL datasource.
   */
  public To0DbStorage(CryptoService cryptoService, DataSource dataSource) {
    this.cryptoService = cryptoService;
    this.dataSource = dataSource;
  }

  @Override
  public byte[] getNonce3() {
    return nonce3;
  }

  @Override
  public void setNonce3(byte[] nonce3) {
    this.nonce3 = nonce3;
  }

  @Override
  public long storeRedirectBlob(Composite voucher, long requestedWait, byte[] signedBlob) {
    Composite ovh = voucher.getAsComposite(Const.OV_HEADER);
    UUID guid = ovh.getAsUuid(Const.OVH_GUID);

    Composite encodedKey = getCryptoService().getOwnerPublicKey(voucher);
    PublicKey pubKey = getCryptoService().decode(encodedKey);
    String ownerX509String = getCryptoService().getFingerPrint(pubKey);
    pubKey = getCryptoService().getDevicePublicKey(voucher);
    Composite deviceX509 = getCryptoService().encode(pubKey, Const.PK_ENC_X509);

    String sql = ""
        + "MERGE INTO RV_REDIRECTS  "
        + "KEY (GUID) "
        + "VALUES (?,?,?,?,?,?,?); ";

    try (Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      pstmt.setString(1, guid.toString());
      pstmt.setBytes(2, signedBlob);
      pstmt.setString(3, ownerX509String);
      pstmt.setBytes(4, deviceX509.toBytes());
      pstmt.setInt(5, Long.valueOf(requestedWait).intValue());
      Timestamp created = new Timestamp(Calendar.getInstance().getTimeInMillis());
      pstmt.setTimestamp(6, created);
      Timestamp expiresAt = new Timestamp(Calendar.getInstance().getTimeInMillis() + requestedWait);
      pstmt.setTimestamp(7, expiresAt);

      pstmt.executeUpdate();

      sql = "SELECT WAIT_SECONDS_RESPONSE FROM RV_REDIRECTS WHERE GUID = ?";
      try (PreparedStatement pstmt2 = conn.prepareStatement(sql)) {

        pstmt2.setString(1, guid.toString());
        try (ResultSet rs = pstmt2.executeQuery()) {
          while (rs.next()) {
            return rs.getInt(1);
          }
        }
      }

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }

    throw new ResourceNotFoundException(guid.toString());
  }

  @Override
  public List<String> getOvKeysAllowlist() {

    List<String> keysInAllowList = new ArrayList<>();

    String sql = "SELECT PUBLIC_KEY_HASH FROM OV_KEYS_ALLOWLIST";

    try (Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      try (ResultSet rs = pstmt.executeQuery()) {
        while (rs.next()) {
          keysInAllowList.add(rs.getString(1));
        }
      }

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
    return keysInAllowList;
  }

  @Override
  public void setOvKeysAllowlist() {

    List<String> allowlist = new ArrayList<>();
    allowlist.add("42110E8F0F3184A1A5C51868BCBFF7144D66E41D1A188103C0264D5DA8BBCF88");
    allowlist.add("707B6451B8319C28E412F847E17BB87995441AF356007A03A3A4AC7745A5223D");
    allowlist.add("25D42F0536CE584E5812AB8750E80E7464742B4B65347BEA90AD4BBC71D3FFA6");
    allowlist.add("283ADF4CCB527C19A72CFB21A9FF7B555788E6B365CEF3A26C6B876EE0FFE017");
    allowlist.add("85A481BBC2DA15EDD7301FF92BA2BB60093D5864A8207F9D78A399B32AB4CFF4");
    allowlist.add("31726603CB0751BFB926B6436369265557855744338FFC3307693E0D14D5241D");
    allowlist.add("2ED65928AD50CB8542E648B9CD5C8B4BFB76DA870C723B16464F49F5140F7098");
    allowlist.add("1DAC184C6A8BB2D00665F4CFC55B1F55AC9BFB4C899B06827C0C1990A1A0F74C");
    allowlist.add("834F83875910C8507CE935BE2F947DCF854E6554C3ACB79893ACF91220EA5D8B");
    allowlist.add("B4E95FB7062303BEB84FBB606ED75CCE99D1C4B6CC88F71E65286CAD7C74F3A5");

    String sql = "INSERT INTO OV_KEYS_ALLOWLIST (PUBLIC_KEY_HASH) VALUES (?);";

    try (Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      for (String s : allowlist) {
        pstmt.setString(1, s);
        pstmt.executeUpdate();
      }

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public List<String> getOvKeysDenylist() {

    List<String> keysInAllowList = new ArrayList<>();

    String sql = "SELECT PUBLIC_KEY_HASH FROM OV_KEYS_DENYLIST";

    try (Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      try (ResultSet rs = pstmt.executeQuery()) {
        while (rs.next()) {
          keysInAllowList.add(rs.getString(1));
        }
      }

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
    return keysInAllowList;
  }

  @Override
  public void setOvKeysDenylist() {

    List<String> denylist = new ArrayList<>();

    String sql = "INSERT INTO OV_KEYS_DENYLIST (PUBLIC_KEY_HASH) VALUES (?);";

    try (Connection conn = dataSource.getConnection();
         PreparedStatement pstmt = conn.prepareStatement(sql)) {

      for (String s : denylist) {
        pstmt.setString(1, s);
        pstmt.executeUpdate();
      }

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void continuing(Composite request, Composite reply) {

    String token = getToken(request);

    String sql = "SELECT NONCE FROM TO0_SESSIONS WHERE SESSION_ID = ?";

    try (Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      pstmt.setString(1, token);

      try (ResultSet rs = pstmt.executeQuery()) {
        while (rs.next()) {
          nonce3 = rs.getBytes(1);
        }
      }

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
    if (nonce3 == null) {
      throw new InvalidJwtException(token);
    }
  }

  @Override
  public void continued(Composite request, Composite reply) {

  }

  @Override
  public void starting(Composite request, Composite reply) {

  }

  @Override
  public void started(Composite request, Composite reply) {

    String sessionId = UUID.randomUUID().toString();
    reply.set(Const.SM_PROTOCOL_INFO,
        Composite.newMap().set(Const.PI_TOKEN, sessionId));

    String sql = "INSERT INTO TO0_SESSIONS (SESSION_ID,NONCE,CREATED) VALUES (?,?,?);";

    try (Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      pstmt.setString(1, sessionId);
      pstmt.setBytes(2, nonce3);
      Timestamp created = new Timestamp(Calendar.getInstance().getTimeInMillis());
      pstmt.setTimestamp(3, created);

      pstmt.executeUpdate();

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void completed(Composite request, Composite reply) {

    String token = getToken(request);

    String sql = "DELETE FROM TO0_SESSIONS WHERE SESSION_ID = ?;";

    try (Connection conn = dataSource.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, token);
      pstmt.executeUpdate();

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public void failed(Composite request, Composite reply) {

  }

  private CryptoService getCryptoService() {
    return cryptoService;
  }

  protected String getToken(Composite request) {
    Composite protocolInfo = request.getAsComposite(Const.SM_PROTOCOL_INFO);
    if (!protocolInfo.containsKey(Const.PI_TOKEN)) {
      throw new InvalidJwtException();
    }
    return protocolInfo.getAsString(Const.PI_TOKEN);
  }

}
