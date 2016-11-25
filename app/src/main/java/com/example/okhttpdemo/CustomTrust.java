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

import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

import okhttp3.OkHttpClient;

public final class CustomTrust {
  public static final String tag = "CustomTrust";
  private static final String CLIENT_KET_PASSWORD = "213679301700631";
  public final OkHttpClient client;
  Context context;
  public CustomTrust(Context context)  {
    this.context = context;
    X509TrustManager trustManager;
    SSLSocketFactory sslSocketFactory=null;

    trustManager = new X509TrustManager() {
      @Override
      public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {

      }

      @Override
      public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {

      }

      @Override
      public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
      }
    };

    try {
    //  trustManager = trustManagerForCertificates(trustedCertificatesInputStream());
      SSLContext sslContext;
      sslContext = SSLContext.getInstance("SSL");
      sslContext.init(null,new X509TrustManager[]{trustManager},null);
      sslSocketFactory = sslContext.getSocketFactory();
    } catch (GeneralSecurityException e) {
      throw new RuntimeException(e);
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

}
