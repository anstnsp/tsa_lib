package com.finger.tsa.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.config.RequestConfig.Builder;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;

import com.finger.tsa.exception.ConException;
import com.google.gson.Gson;

public class HttpConnectionConfig {
 
	private static final Log LOG = LogFactory.getLog(HttpConnectionConfig.class);
    private final static int SOCKET_TIMEOUT = 5000;
    private final static int CONNECT_TIMEOUT = 3000;
    private final static int MAX_CONN_TOTAL = 100;
    private final static int MAX_CONN_PER_ROUTE = 5;
    
    private static HttpClient instance; 
    private HttpConnectionConfig() {}

    public static HttpClient getHttpClient() {
    	if (instance == null) {
    		instance = HttpClientBuilder.create() 
                    .setMaxConnTotal(MAX_CONN_TOTAL)
                    .setMaxConnPerRoute(MAX_CONN_PER_ROUTE)
                    .build();

            return instance;
    	} else {

            return instance;
    		
    	}
    }

    public static HttpResponse doPost(String url, Object dto) throws ClientProtocolException, ConException, UnsupportedEncodingException  {
	  Builder builder = RequestConfig.custom();
      builder.setConnectTimeout(CONNECT_TIMEOUT);
      builder.setSocketTimeout(SOCKET_TIMEOUT);
      RequestConfig config = builder.build();
      
      HttpPost request = new HttpPost(url);
      request.setHeader("Connection", "keep-alive");
      request.setHeader("Content-Type", "application/json");
      request.setConfig(config);	
 
      Gson gson = new Gson();
      String serialDto = gson.toJson(dto);
      try {
    	  request.setEntity(new StringEntity(serialDto));  //UnsupportedEncodingException
    	  return instance.execute(request);
	  } catch (ClientProtocolException e) {
		  LOG.error("Malformed url, msg:"+e.getMessage());
		  throw e;
	  } catch (UnsupportedEncodingException e) {
		  LOG.error("지원하지 않는 인코딩" );
		  throw e;
	  } catch (IOException e) {
		  LOG.error("Fail to Communication to TSA_SERVER, msg:"+e.getMessage());
		  throw new ConException("Fail to Communication to TSA_SERVER");
	  } 
    }
}
 

