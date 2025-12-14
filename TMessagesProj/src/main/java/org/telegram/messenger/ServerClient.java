package org.telegram.messenger;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.AsyncTask;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class ServerClient {
    public static String getServerBase(Context context) {
        SharedPreferences prefs = context.getSharedPreferences("server_config", Context.MODE_PRIVATE);
        return prefs.getString("server_address", "http://127.0.0.1:8080");
    }

    public static void setServerBase(Context context, String address) {
        context.getSharedPreferences("server_config", Context.MODE_PRIVATE).edit().putString("server_address", address).apply();
    }

    public interface StringCallback {
        void onSuccess(String body);
        void onError(Exception e);
    }

    public static void postRegister(final Context context, final long userId, final StringCallback cb) {
        new AsyncTask<Void, Void, Object>() {
            @Override
            protected Object doInBackground(Void... voids) {
                try {
                    URL url = new URL(getServerBase(context) + "/api/v1/register");
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(15000);
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                    conn.setDoOutput(true);
                    String body = "{\"userid\":" + userId + "}";
                    OutputStream os = conn.getOutputStream();
                    os.write(body.getBytes("UTF-8"));
                    os.close();
                    int code = conn.getResponseCode();
                    InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
                    BufferedReader br = new BufferedReader(new InputStreamReader(is));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line).append('\n');
                    br.close();
                    return sb.toString();
                } catch (Exception e) {
                    return e;
                }
            }

            @Override
            protected void onPostExecute(Object res) {
                if (res instanceof Exception) {
                    cb.onError((Exception) res);
                } else {
                    cb.onSuccess((String) res);
                }
            }
        }.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }

    public static void postVerify(final Context context, final long userId, final String publicKey, final String verifySecret, final StringCallback cb) {
        new AsyncTask<Void, Void, Object>() {
            @Override
            protected Object doInBackground(Void... voids) {
                try {
                    URL url = new URL(getServerBase(context) + "/api/v1/verify");
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(15000);
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
                    conn.setDoOutput(true);
                    String body = "{\"userid\":" + userId + ",\"public_key\":\"" + publicKey.replace("\"","\\\"") + "\",\"verify_secret\":\"" + verifySecret.replace("\"","\\\"") + "\"}";
                    OutputStream os = conn.getOutputStream();
                    os.write(body.getBytes("UTF-8"));
                    os.close();
                    int code = conn.getResponseCode();
                    InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
                    BufferedReader br = new BufferedReader(new InputStreamReader(is));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line).append('\n');
                    br.close();
                    return sb.toString();
                } catch (Exception e) {
                    return e;
                }
            }

            @Override
            protected void onPostExecute(Object res) {
                if (res instanceof Exception) {
                    cb.onError((Exception) res);
                } else {
                    cb.onSuccess((String) res);
                }
            }
        }.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }

    public static void getPublicKey(final Context context, final long userId, final StringCallback cb) {
        new AsyncTask<Void, Void, Object>() {
            @Override
            protected Object doInBackground(Void... voids) {
                try {
                    URL url = new URL(getServerBase(context) + "/api/v1/get_public_key/" + userId);
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setConnectTimeout(10000);
                    conn.setReadTimeout(15000);
                    conn.setRequestMethod("GET");
                    int code = conn.getResponseCode();
                    InputStream is = (code >= 200 && code < 400) ? conn.getInputStream() : conn.getErrorStream();
                    BufferedReader br = new BufferedReader(new InputStreamReader(is));
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) sb.append(line).append('\n');
                    br.close();
                    return sb.toString();
                } catch (Exception e) {
                    return e;
                }
            }

            @Override
            protected void onPostExecute(Object res) {
                if (res instanceof Exception) {
                    cb.onError((Exception) res);
                } else {
                    cb.onSuccess((String) res);
                }
            }
        }.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR);
    }
}
