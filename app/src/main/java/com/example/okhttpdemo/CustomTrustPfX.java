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

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Arrays;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.CertificatePinner;
import okhttp3.OkHttpClient;

public final class CustomTrustPfX {
  public static final String tag = "CustomTrust";
  private static final String CLIENT_KET_PASSWORD = "213679301700631";
  public final OkHttpClient client;
  Context context;
  public CustomTrustPfX(Context context)  {
    this.context = context;
    X509TrustManager trustManager;
    SSLSocketFactory sslSocketFactory=null;

//    trustManager = new X509TrustManager() {
//      @Override
//      public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
//
//      }
//
//      @Override
//      public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
//
//      }
//
//      @Override
//      public X509Certificate[] getAcceptedIssuers() {
//        return new X509Certificate[0];
//      }
//    };

    try {
    //  trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
      SSLContext sslContext =  trustManagerForCertificates(trustedCertificatesInputStream()); //SSLContext.getInstance("TLS");
    //  sslContext = SSLContext.getInstance("SSL");
     // sslContext.init(null,new X509TrustManager[]{trustManager},null);
      sslSocketFactory = sslContext.getSocketFactory();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
    } catch (IOException e) {
      e.printStackTrace();
    }
    client = new OkHttpClient.Builder()
        .sslSocketFactory(sslSocketFactory).hostnameVerifier(new HostnameVerifier() {
              @Override
              public boolean verify(String hostname, SSLSession session) {
                return true;
              }
            })
        .build();

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
  private SSLContext trustManagerForCertificates(InputStream in)
          throws GeneralSecurityException, IOException {

    // Put the certificates a key store.
    char[] password = CLIENT_KET_PASSWORD.toCharArray(); // Any password will work.
    KeyStore keyStore = newEmptyKeyStore(password);
    keyStore.load(in,CLIENT_KET_PASSWORD.toCharArray());

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

    SSLContext ssContext = SSLContext.getInstance("TLS");
    ssContext.init(keyManagerFactory.getKeyManagers(),trustManagers,null);
    return  ssContext;
  }

  private KeyStore newEmptyKeyStore(char[] password) throws GeneralSecurityException {
    try {
      KeyStore keyStore = KeyStore.getInstance("PKCS12");
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
