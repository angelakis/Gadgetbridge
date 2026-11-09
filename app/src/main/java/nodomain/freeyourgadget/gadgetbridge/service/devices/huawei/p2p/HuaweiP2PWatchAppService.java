/*  Copyright (C) 2026 Gadgetbridge contributors

    This file is part of Gadgetbridge.

    Gadgetbridge is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Gadgetbridge is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>. */
package nodomain.freeyourgadget.gadgetbridge.service.devices.huawei.p2p;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.text.TextUtils;
import android.util.Base64;

import androidx.annotation.Nullable;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import nodomain.freeyourgadget.gadgetbridge.GBApplication;
import nodomain.freeyourgadget.gadgetbridge.devices.huawei.packets.P2P;
import nodomain.freeyourgadget.gadgetbridge.externalevents.IntentApiReceiver;
import nodomain.freeyourgadget.gadgetbridge.service.devices.huawei.HuaweiP2PManager;

/**
 * Messaging with a third-party (debug-profile signed) app on a Huawei lite wearable,
 * over Wear Engine P2P (service 0x34).
 * <p>
 * Watch side: the app talks to the phone package {@link #PHONE_PACKAGE} with the phone fingerprint
 * {@link #PHONE_FINGERPRINT} (Wear Engine setPackageName / setFingerprint + sendMsg / subscribeMsg).
 * Both values are arbitrary strings that only have to match on both sides.
 * <p>
 * Phone side, both gated by the per-device Intent API setting "Allow messages to watch apps":
 * <ul>
 *   <li>To the watch: the generic {@link IntentApiReceiver#COMMAND_SEND_WATCH_APP_MESSAGE} with
 *       appId = the watch app's package and payload = the message text.</li>
 *   <li>From the watch: every message is broadcast as {@link #ACTION_WATCH_APP_MESSAGE_RECEIVED}
 *       with the same extras (appId, payload) plus device = the watch's address.</li>
 * </ul>
 * The watch identifies an app by its package plus the public key of the developer certificate
 * it was signed with. That identity is read from the .bin when the app is installed through
 * Gadgetbridge, stored per device, and a service is registered for it on every connect.
 */
public class HuaweiP2PWatchAppService extends HuaweiBaseP2PService {
    private static final Logger LOG = LoggerFactory.getLogger(HuaweiP2PWatchAppService.class);

    public static final String PHONE_PACKAGE = "nodomain.freeyourgadget.gadgetbridge";
    // Arbitrary 64 hex characters (SHA-256 shaped). This is the value HuaSideload uses, so watch apps
    // built from its bridge.js only need their phone package set to PHONE_PACKAGE.
    public static final String PHONE_FINGERPRINT = "CA612C488CBB19EE1601EAFFFE084ED6AC674AF264A861D9101CF1A3A191693E";

    public static final String ACTION_WATCH_APP_MESSAGE_RECEIVED = "nodomain.freeyourgadget.gadgetbridge.WATCH_APP_MESSAGE_RECEIVED";
    public static final String EXTRA_APP_ID = "appId";
    public static final String EXTRA_PAYLOAD = "payload";
    public static final String EXTRA_DEVICE = "device";

    // Device specific: JSON object {"<watch app package>": "<watch app fingerprint>"}
    public static final String PREF_KNOWN_APPS = "huawei_watchapp_p2p_identities";

    private static final int CODE_OK = 0xcf;
    private static final int CODE_PING_REPLY = 0xcd;

    private final String watchPackage;
    private final String watchFingerprint;

    public HuaweiP2PWatchAppService(HuaweiP2PManager manager, String watchPackage, String watchFingerprint) {
        super(manager);
        this.watchPackage = watchPackage;
        this.watchFingerprint = watchFingerprint;
    }

    @Override
    public String getModule() {
        return PHONE_PACKAGE;
    }

    @Override
    public String getPackage() {
        return watchPackage;
    }

    @Override
    public String getFingerprint() {
        return watchFingerprint;
    }

    @Override
    public String getLocalFingerprint() {
        return PHONE_FINGERPRINT;
    }

    @Override
    public void registered() {
        LOG.info("Watch app service registered for {}", watchPackage);
    }

    @Override
    public void unregister() {
    }

    public void sendMessage(byte[] data) {
        if (data.length > 1000) {
            LOG.warn("Message to {} is {} bytes; Wear Engine recommends at most 1 KB", watchPackage, data.length);
        }
        sendCommand(data, (code, respData) -> {
            if (code != CODE_OK) {
                LOG.warn("Watch app {} did not accept the message, code 0x{}", watchPackage, Integer.toHexString(code));
            }
        });
    }

    @Override
    public void handlePacket(P2P.P2PCommand.Response packet) {
        // A message started by the watch app can carry the sequence number of one of our pending
        // sends; it is not the reply to it, so data packets never go to the reply callbacks.
        if (packet.cmdId == 2) {
            manager.sendAck(packet.sequenceId, packet.dstPackage, packet.srcPackage, CODE_OK);
            handleData(packet.respData);
            return;
        }
        super.handlePacket(packet);
    }

    @Override
    protected int onPingPacket(P2P.P2PCommand.Response packet) {
        return CODE_PING_REPLY;
    }

    @Override
    public void handleData(byte[] data) {
        if (data == null) {
            return;
        }
        final String message = new String(data, StandardCharsets.UTF_8);
        LOG.debug("Message from watch app {}: {}", watchPackage, message);
        if (!devicePrefs(manager).getBoolean(IntentApiReceiver.THIRD_PARTY_APPS_WATCH_APP_MESSAGES, false)) {
            LOG.info("Not broadcasting message from {}: watch app messages are not allowed in the Intent API settings", watchPackage);
            return;
        }
        final Intent intent = new Intent(ACTION_WATCH_APP_MESSAGE_RECEIVED);
        intent.putExtra(EXTRA_APP_ID, watchPackage);
        intent.putExtra(EXTRA_PAYLOAD, message);
        intent.putExtra(EXTRA_DEVICE, manager.getSupportProvider().getDevice().getAddress());
        getContext().sendBroadcast(intent);
    }

    private Context getContext() {
        return manager.getSupportProvider().getContext();
    }

    // ---- Registration ----

    @Nullable
    public static HuaweiP2PWatchAppService getRegisteredInstance(HuaweiP2PManager manager, String watchPackage) {
        return (HuaweiP2PWatchAppService) manager.getRegisteredService(PHONE_PACKAGE, watchPackage);
    }

    public static void registerKnownApps(HuaweiP2PManager manager) {
        for (Map.Entry<String, String> app : getKnownApps(manager).entrySet()) {
            if (getRegisteredInstance(manager, app.getKey()) == null) {
                new HuaweiP2PWatchAppService(manager, app.getKey(), app.getValue()).register();
            }
        }
    }

    /**
     * Remember the identity of a watch app installed through Gadgetbridge and start listening to it.
     */
    public static void rememberApp(HuaweiP2PManager manager, String watchPackage, String watchFingerprint) {
        if (TextUtils.isEmpty(watchPackage) || TextUtils.isEmpty(watchFingerprint)) {
            return;
        }
        final Map<String, String> apps = getKnownApps(manager);
        apps.put(watchPackage, watchFingerprint);
        devicePrefs(manager).edit().putString(PREF_KNOWN_APPS, new JSONObject(apps).toString()).apply();
        LOG.info("Remembered watch app {} for P2P messaging", watchPackage);
        // Replaces a registration from an earlier install with a different certificate
        new HuaweiP2PWatchAppService(manager, watchPackage, watchFingerprint).register();
    }

    private static Map<String, String> getKnownApps(HuaweiP2PManager manager) {
        final Map<String, String> apps = new HashMap<>();
        final String json = devicePrefs(manager).getString(PREF_KNOWN_APPS, null);
        if (TextUtils.isEmpty(json)) {
            return apps;
        }
        try {
            final JSONObject obj = new JSONObject(json);
            final Iterator<String> keys = obj.keys();
            while (keys.hasNext()) {
                final String key = keys.next();
                apps.put(key, obj.getString(key));
            }
        } catch (JSONException e) {
            LOG.error("Could not read the stored watch app identities", e);
        }
        return apps;
    }

    private static SharedPreferences devicePrefs(HuaweiP2PManager manager) {
        return GBApplication.getDeviceSpecificSharedPrefs(manager.getSupportProvider().getDevice().getAddress());
    }

    // ---- Identity of a signed watch app (.bin) ----

    /**
     * The identity the watch uses for a signed app (appverify GetAppid):
     * package + "_" + base64 of the developer certificate's EC public key as an uncompressed point.
     * The certificate is in the provisioning profile embedded in the signature block at the end of the .bin.
     *
     * @return null if the file has no readable profile or certificate
     */
    @Nullable
    public static String fingerprintFromBin(byte[] bin, String watchPackage) {
        if (bin == null || TextUtils.isEmpty(watchPackage)) {
            return null;
        }
        try {
            final int tailStart = Math.max(0, bin.length - 64 * 1024);
            final String tail = new String(bin, tailStart, bin.length - tailStart, StandardCharsets.ISO_8859_1);
            final int start = tail.indexOf("{\"version-name\"");
            if (start < 0) {
                LOG.warn("No provisioning profile found in the watch app");
                return null;
            }
            int depth = 0;
            int end = -1;
            for (int i = start; i < tail.length(); i++) {
                final char c = tail.charAt(i);
                if (c == '{') depth++;
                if (c == '}') {
                    depth--;
                    if (depth == 0) {
                        end = i + 1;
                        break;
                    }
                }
            }
            if (end < 0) {
                return null;
            }
            // ISO-8859-1 kept the bytes 1:1; the profile itself is UTF-8 JSON
            final String profileJson = new String(tail.getBytes(StandardCharsets.ISO_8859_1), start, end - start, StandardCharsets.UTF_8);
            final JSONObject bundleInfo = new JSONObject(profileJson).getJSONObject("bundle-info");
            String pem = bundleInfo.optString("development-certificate", "");
            if (pem.isEmpty()) {
                pem = bundleInfo.optString("distribution-certificate", "");
            }
            if (pem.isEmpty()) {
                return null;
            }
            final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
            if (!(cert.getPublicKey() instanceof ECPublicKey)) {
                LOG.warn("Watch app certificate does not have an EC key");
                return null;
            }
            final ECPublicKey key = (ECPublicKey) cert.getPublicKey();
            final int size = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
            final byte[] point = new byte[1 + 2 * size];
            point[0] = 0x04;
            copyUnsigned(key.getW().getAffineX(), point, 1, size);
            copyUnsigned(key.getW().getAffineY(), point, 1 + size, size);
            return watchPackage + "_" + Base64.encodeToString(point, Base64.NO_WRAP);
        } catch (Exception e) {
            LOG.error("Could not read the developer certificate of the watch app", e);
            return null;
        }
    }

    // Big-endian, left-padded to exactly `size` bytes (BigInteger may add a sign byte or be shorter)
    private static void copyUnsigned(BigInteger value, byte[] out, int offset, int size) {
        final byte[] bytes = value.toByteArray();
        final int skip = Math.max(0, bytes.length - size);
        final int len = bytes.length - skip;
        System.arraycopy(bytes, skip, out, offset + size - len, len);
    }
}
