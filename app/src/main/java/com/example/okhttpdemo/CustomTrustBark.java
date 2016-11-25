/*
 * Copyright (C) 2015 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.okhttpdemo;

import android.content.Context;

import com.vpnet.NetLog;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Arrays;
import java.util.Collection;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.CertificatePinner;
import okhttp3.Headers;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public final class CustomTrustBark {
  public static final String tag = "CustomTrust";
  public final OkHttpClient client;
  Context context;
  public CustomTrustBark(Context context) {
    this.context = context;
    X509TrustManager trustManager;
    SSLSocketFactory sslSocketFactory;
    try {
      trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
      SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, new TrustManager[] { trustManager }, null);
      sslSocketFactory = sslContext.getSocketFactory();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    }

    client = new OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory)
        .build();
  }

  public void run(String url ) throws Exception {
    Request request = new Request.Builder()
        .url("https://publicobject.com/helloworld.txt")
        .build();

     client.newCall(request).enqueue(new Callback() {
      @Override
      public void onFailure(Call call, IOException e) {
        e.printStackTrace();
        NetLog.d(tag,"failure:" + e.getMessage());
      }

      @Override
      public void onResponse(Call call, Response response) throws IOException {
        if (!response.isSuccessful()) throw new IOException("Unexpected code " + response);

        Headers responseHeaders = response.headers();
        for (int i = 0; i < responseHeaders.size(); i++) {
          System.out.println(responseHeaders.name(i) + ": " + responseHeaders.value(i));
        }
        NetLog.d(tag,"onResponse:" +response.body().string());
        //System.out.println(response.body().string());
      }
    });

  }

  /**
   * Returns an input stream containing one or more certificate PEM files. This implementation just
   * embeds the PEM files in Java strings; most applications will instead read this from a resource
   * file that gets bundled with the application.
   */
  private InputStream trustedCertificatesInputStream() {
    // PEM files for root certificates of Comodo and Entrust. These two CAs are sufficient to view
    // https://publicobject.com (Comodo) and https://squareup.com (Entrust). But they aren't
    // sufficient to connect to most HTTPS sites including https://godaddy.com and https://visa.com.
    // Typically developers will need to get a PEM file from their organization's TLS administrator.

    return context.getResources().openRawResource(R.raw.b213679301700631) ;

    /*return new Buffer()
        .writeUtf8(comodoRsaCertificationAuthority)
        .writeUtf8(entrustRootCertificateAuthority)
        .inputStream();*/
  }

  /**
   * Returns a trust manager that trusts {@code certificates} and none other. HTTPS services whose
   * certificates have not been signed by these certificates will fail with a {@code
   * SSLHandshakeException}.
   *
   * <p>This can be used to replace the host platform's built-in trusted certificates with a custom
   * set. This is useful in development where certificate authority-trusted certificates aren't
   * available. Or in production, to avoid reliance on third-party certificate authorities.
   *
   * <p>See also {@link CertificatePinner}, which can limit trusted certificates while still using
   * the host platform's built-in trust store.
   *
   * <h3>Warning: Customizing Trusted Certificates is Dangerous!</h3>
   *
   * <p>Relying on your own trusted certificates limits your server team's ability to update their
   * TLS certificates. By installing a specific set of trusted certificates, you take on additional
   * operational complexity and limit your ability to migrate between certificate authorities. Do
   * not use custom trusted certificates in production without the blessing of your server's TLS
   * administrator.
   */
  private X509TrustManager trustManagerForCertificates(InputStream in)
      throws GeneralSecurityException {
    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
    Collection<? extends Certificate> certificates = certificateFactory.generateCertificates(in);
    if (certificates.isEmpty()) {
      throw new IllegalArgumentException("expected non-empty set of trusted certificates");
    }

    // Put the certificates a key store.
    char[] password = "213679301700631".toCharArray(); // Any password will work.
    KeyStore keyStore = newEmptyKeyStore(password);
    int index = 0;
    for (Certificate certificate : certificates) {
      String certificateAlias = Integer.toString(index++);
      keyStore.setCertificateEntry(certificateAlias, certificate);
    }

    // Use it to build an X509 trust manager.
    KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
        KeyManagerFactory.getDefaultAlgorithm());
    keyManagerFactory.init(keyStore, password);
    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(keyStore);
    TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
    if (trustManagers.length != 1 || !(trustManagers[0] instanceof X509TrustManager)) {
      throw new IllegalStateException("Unexpected default trust managers:"
          + Arrays.toString(trustManagers));
    }
    return (X509TrustManager) trustManagers[0];
  }

  private KeyStore newEmptyKeyStore(char[] password) throws GeneralSecurityException {
    try {
      KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
      InputStream in = null; // By convention, 'null' creates an empty key store.
      keyStore.load(in, password);
      return keyStore;
    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

//  public static void main(String... args) throws Exception {
//    new CustomTrust().run();
//  }
}
