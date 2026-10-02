package org.droidrecon.companion;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.ComponentName;
import android.content.Intent;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.OperationCanceledException;
import android.os.Process;
import android.util.Base64;
import android.util.Log;

import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Sends one bounded IPC request from an ordinary application UID. The only returned
 * provider information is whether one row exists, its column count, or whether a
 * call returned a Bundle. No provider values are read or logged. All results are
 * correlated by a host-generated nonce.
 */
public final class ProbeActivity extends Activity {
    private static final String TAG = "DroidReconCompanion";
    private static final String RESULT_PREFIX = "DR_RESULT:";
    private static final int MAX_ENCODED_PAYLOAD = 8192;
    private static final int MAX_FIELD = 4096;
    private static final int PROBE_TIMEOUT_SECONDS = 12;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        handle(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        handle(intent);
    }

    private static String required(JSONObject request, String key) throws Exception {
        String value = request.getString(key);
        if (value.isEmpty() || value.length() > MAX_FIELD) {
            throw new IllegalArgumentException("invalid " + key);
        }
        return value;
    }

    private void handle(Intent launchIntent) {
        final JSONObject request;
        try {
            String encoded = launchIntent.getStringExtra("payload");
            if (encoded == null || encoded.length() > MAX_ENCODED_PAYLOAD) {
                throw new IllegalArgumentException("missing or oversized payload");
            }
            byte[] decoded = Base64.decode(encoded, Base64.URL_SAFE | Base64.NO_WRAP);
            request = new JSONObject(new String(decoded, StandardCharsets.UTF_8));
        } catch (Exception error) {
            Log.i(TAG, RESULT_PREFIX + "{\"status\":\"invalid_request\"}");
            finish();
            return;
        }

        final String id = request.optString("id", "");
        final String operation = request.optString("operation", "");
        final CancellationSignal cancellation = new CancellationSignal();
        final ExecutorService worker = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "droid-recon-probe");
            thread.setDaemon(true);
            return thread;
        });
        final Future<JSONObject> future = worker.submit(() -> execute(request, cancellation));

        Thread supervisor = new Thread(() -> {
            JSONObject result;
            try {
                result = future.get(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException error) {
                cancellation.cancel();
                future.cancel(true);
                result = baseResult(id, operation, "timeout");
            } catch (Exception error) {
                result = baseResult(id, operation, "error");
                put(result, "exception", error.getClass().getSimpleName());
            } finally {
                worker.shutdownNow();
            }
            Log.i(TAG, RESULT_PREFIX + result);
            runOnUiThread(this::finish);
        }, "droid-recon-supervisor");
        supervisor.setDaemon(true);
        supervisor.start();
    }

    private JSONObject execute(JSONObject request, CancellationSignal cancellation) {
        String id = request.optString("id", "");
        String operation = request.optString("operation", "");
        JSONObject result = baseResult(id, operation, "error");
        try {
            if (!id.matches("[0-9a-f]{32}")) {
                throw new IllegalArgumentException("invalid id");
            }
            String target = required(request, "target_package");
            if (!target.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")) {
                throw new IllegalArgumentException("invalid target package");
            }
            if (operation.equals("activity") || operation.equals("service")
                    || operation.equals("broadcast")) {
                String component = required(request, "component");
                if (!component.matches("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)+")) {
                    throw new IllegalArgumentException("invalid component class");
                }
                Intent intent = new Intent();
                intent.setComponent(new ComponentName(target, component));
                if (operation.equals("activity")) {
                    intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                    startActivity(intent);
                    put(result, "status", "accepted_by_os");
                } else if (operation.equals("service")) {
                    ComponentName started = startService(intent);
                    put(result, "status", started == null ? "not_found" : "accepted_by_os");
                } else {
                    String action = request.optString("action", "");
                    if (action.length() > MAX_FIELD) {
                        throw new IllegalArgumentException("oversized action");
                    }
                    if (!action.isEmpty()) {
                        intent.setAction(action);
                    }
                    sendBroadcast(intent);
                    // sendBroadcast has no delivery acknowledgement.
                    put(result, "status", "dispatched_unconfirmed");
                }
            } else if (operation.equals("deeplink")) {
                Uri uri = Uri.parse(required(request, "uri"));
                if (uri.getScheme() == null) {
                    throw new IllegalArgumentException("deep link has no scheme");
                }
                Intent intent = new Intent(Intent.ACTION_VIEW, uri);
                intent.addCategory(Intent.CATEGORY_BROWSABLE);
                intent.setPackage(target);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
                startActivity(intent);
                put(result, "status", "accepted_by_os");
            } else if (operation.equals("provider_query")) {
                Uri uri = Uri.parse(required(request, "uri"));
                if (!"content".equals(uri.getScheme()) || uri.getAuthority() == null) {
                    throw new IllegalArgumentException("provider URI must be content://");
                }
                try (Cursor cursor = getContentResolver().query(
                        uri, null, null, null, null, cancellation)) {
                    if (cursor == null) {
                        put(result, "status", "null_cursor_unconfirmed");
                    } else {
                        put(result, "status", "queried");
                        put(result, "has_row", cursor.moveToFirst());
                        put(result, "column_count", cursor.getColumnCount());
                    }
                }
            } else if (operation.equals("provider_call")) {
                Uri uri = Uri.parse(required(request, "uri"));
                if (!"content".equals(uri.getScheme()) || uri.getAuthority() == null) {
                    throw new IllegalArgumentException("provider URI must be content://");
                }
                String method = required(request, "method");
                if (method.length() > 256) {
                    throw new IllegalArgumentException("oversized provider method");
                }
                for (int index = 0; index < method.length(); index++) {
                    char character = method.charAt(index);
                    if (character < 32 || character == 127) {
                        throw new IllegalArgumentException("invalid provider method");
                    }
                }
                // This is only requested explicitly. Provider-defined call methods
                // can have side effects; never send an argument or extras, and never
                // inspect or log returned Bundle values.
                Bundle response = getContentResolver().call(
                        uri.getAuthority(), method, null, null);
                put(result, "status", "accepted_by_os");
                put(result, "has_result", response != null);
            } else {
                throw new IllegalArgumentException("unknown operation");
            }
        } catch (SecurityException error) {
            put(result, "status", "denied");
            put(result, "exception", error.getClass().getSimpleName());
        } catch (ActivityNotFoundException error) {
            put(result, "status", "not_found");
        } catch (OperationCanceledException error) {
            put(result, "status", "timeout");
        } catch (IllegalStateException error) {
            put(result, "status", "blocked_by_platform");
            put(result, "exception", error.getClass().getSimpleName());
        } catch (Exception error) {
            put(result, "status", "error");
            put(result, "exception", error.getClass().getSimpleName());
        }
        return result;
    }

    private JSONObject baseResult(String id, String operation, String status) {
        JSONObject result = new JSONObject();
        put(result, "id", id);
        put(result, "operation", operation);
        put(result, "status", status);
        put(result, "caller_package", getPackageName());
        put(result, "caller_uid", Process.myUid());
        return result;
    }

    private static void put(JSONObject object, String key, Object value) {
        try {
            object.put(key, value);
        } catch (Exception ignored) {
            // JSON keys and primitive values above are fixed, so this is unreachable.
        }
    }
}
