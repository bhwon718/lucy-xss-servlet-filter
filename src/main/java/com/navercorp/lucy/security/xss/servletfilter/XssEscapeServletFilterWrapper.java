/*
 * Copyright 2014 NAVER Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.navercorp.lucy.security.xss.servletfilter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.*;

/**
 * @author todtod80
 * @author leeplay
 */
public class XssEscapeServletFilterWrapper extends HttpServletRequestWrapper {
	private static final Log LOG = LogFactory.getLog(XssEscapeServletFilterWrapper.class);
	private XssEscapeFilter xssEscapeFilter;
	private String path;
	private ObjectMapper mapper = new ObjectMapper();
	private boolean isJson;

	public XssEscapeServletFilterWrapper(ServletRequest request, XssEscapeFilter xssEscapeFilter) {
		super((HttpServletRequest)request);
		isJson = isJsonContent((HttpServletRequest)request);

		this.xssEscapeFilter = xssEscapeFilter;

		String contextPath = ((HttpServletRequest)request).getContextPath();
		this.path = ((HttpServletRequest)request).getRequestURI().substring(contextPath.length());
	}

	@Override
	public String getParameter(String paramName) {
		String value = super.getParameter(paramName);
		return doFilter(paramName, value);
	}

	@Override
	public String[] getParameterValues(String paramName) {
		String values[] = super.getParameterValues(paramName);
		if(values == null) {
			return values;
		}
		for(int index = 0; index < values.length; index++) {
			values[index] = doFilter(paramName, values[index]);
		}
		return values;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Map<String, Object> getParameterMap() {
		Map<String, Object> paramMap = super.getParameterMap();
		Map<String, Object> newFilteredParamMap = new HashMap<String, Object>();

		Set<Map.Entry<String, Object>> entries = paramMap.entrySet();
		for(Map.Entry<String, Object> entry : entries) {
			String paramName = entry.getKey();
			Object[] valueObj = (Object[])entry.getValue();
			String[] filteredValue = new String[valueObj.length];
			for(int index = 0; index < valueObj.length; index++) {
				filteredValue[index] = doFilter(paramName, String.valueOf(valueObj[index]));
			}

			newFilteredParamMap.put(entry.getKey(), filteredValue);
		}

		return newFilteredParamMap;
	}

	/****
	 * application/json 일때 사용하는 inputStream 에도 필터링
	 * 단, multipart 데이터로 넘어오는 경우에도 해당 stream 을 사용할 수 있는데, 이때는 exception 나와서 그냥 원본 inputStream 넘기도록 해준다.
	 * @return
	 */
	@Override
	public ServletInputStream getInputStream() throws IOException {

		try {
			if(!xssEscapeFilter.isGlobalDisableURL(this.path) && isJson){
				String inputString = IOUtils.toString(super.getInputStream(), getCharacterEncoding());
				String outputString = filterJson(inputString);
				return new XssFilteredServletInputStream(new ByteArrayInputStream(outputString.getBytes(getCharacterEncoding())));
			}
		} catch(IOException ioe) {
			LOG.error(ioe.getMessage(),ioe);
		}
		return super.getInputStream();
	}

	public String filterJson(String input) throws JsonProcessingException {
		if(LOG.isDebugEnabled()) {
			LOG.debug("input :: " + input.toString());
		}
		mapper = new ObjectMapper();
		JsonNode jsonNode = mapper.readTree(input);
		return mapper.writeValueAsString(filterJsonNode(jsonNode));

	}

	private JsonNode filterJsonNode(JsonNode jsonNode){
		if(LOG.isDebugEnabled()) {
			LOG.debug("jsonNode.toPrettyString() :: " + jsonNode.toPrettyString());
		}
		if (jsonNode.isObject()) {
			Iterator<Map.Entry<String, JsonNode>> fields = jsonNode.fields();
			fields.forEachRemaining(field -> {
				if(LOG.isDebugEnabled()) {
					LOG.debug("field.getValue() instanceof : " + field.getValue().getClass().getName());
					LOG.debug("field.getKey() :: " + field.getKey());
					LOG.debug("field.getValue() :: " + field.getValue());
				}
				if(field.getValue().isObject() || field.getValue().isArray()){
					filterJsonNode(field.getValue());
				}else if(field.getValue()!=null && field.getValue() instanceof TextNode){
					String key = field.getKey();
					String value = field.getValue().textValue();
					field.setValue(new TextNode(doFilter(key, value)));
				}
			});
		} else if (jsonNode.isArray()) {
			ArrayNode arrayField = (ArrayNode) jsonNode;
			arrayField.forEach(node -> {
				filterJsonNode(node);
			});
		}
		return jsonNode;
	}

	public class XssFilteredServletInputStream extends ServletInputStream {
		private ByteArrayInputStream input;

		public XssFilteredServletInputStream(ByteArrayInputStream bis) {
			input = bis;
		}

		@Override
		public int read() {
			return input.read();
		}
	}

	public boolean isMultipartContent(HttpServletRequest request) {
		String contentType = request.getContentType();
		if(contentType == null) {
			return false;
		}
		if(contentType.toLowerCase().startsWith("multipart/form-data")) {
			return true;
		}
		return false;
	}

	public boolean isJsonContent(HttpServletRequest request) {
		String contentType = request.getContentType();
		if(contentType == null) {
			return false;
		}
		if(contentType.toLowerCase().startsWith("application/json")) {
			return true;
		}
		return false;
	}


	/**
	 * @param paramName String
	 * @param value     String
	 * @return String
	 */
	private String doFilter(String paramName, String value) {
		return xssEscapeFilter.doFilter(this.path, paramName, value);
	}
}
