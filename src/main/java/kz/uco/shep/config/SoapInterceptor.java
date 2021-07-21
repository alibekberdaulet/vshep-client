package kz.uco.shep.config;

import kz.uco.shep.utils.XMLSignUtils;
import org.apache.ws.security.WSSecurityException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.client.WebServiceClientException;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.saaj.SaajSoapMessage;

import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class SoapInterceptor implements ClientInterceptor {
    private final static Logger log = LoggerFactory.getLogger(SoapInterceptor.class);

    @Override
    public boolean handleResponse(MessageContext messageContext) throws WebServiceClientException {
        log.info("#### SOAP RESPONSE ####");
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            messageContext.getResponse().writeTo(buffer);
            String payload = buffer.toString(java.nio.charset.StandardCharsets.UTF_8.name());
            if (payload.length() > 1000000) {
                log.info("Длина строки ответа = " + payload.length());
                log.info("Ответ слишком большой...");
            } else {
                log.info(payload);
            }

        } catch (IOException e) {
            throw new WebServiceClientException("Can not write the SOAP response into the out stream", e) {
                private static final long serialVersionUID = 408300824707285733L;
            };
        }

        return true;
    }

    @Override
    public boolean handleRequest(MessageContext messageContext) throws WebServiceClientException {

        log.info("#### SOAP REQUEST ####");

        try {
            SaajSoapMessage soapMessage = (SaajSoapMessage) messageContext.getRequest();
            SOAPMessage mes = soapMessage.getSaajMessage();

            try {
                XMLSignUtils.signSoap(mes.getSOAPPart().getEnvelope());
            } catch (XMLSecurityException e) {
                e.printStackTrace();
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            } catch (KeyStoreException e) {
                e.printStackTrace();
            } catch (PrivilegedActionException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnrecoverableKeyException e) {
                e.printStackTrace();
            } catch (SOAPException e) {
                e.printStackTrace();
            } catch (WSSecurityException e) {
                e.printStackTrace();
            }

            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            messageContext.getRequest().writeTo(buffer);
            String payload = buffer.toString(java.nio.charset.StandardCharsets.UTF_8.name());

            log.info(payload);

        } catch (IOException e) {
            throw new WebServiceClientException("Can not write the SOAP request into the out stream", e) {
                private static final long serialVersionUID = 5428645925507939749L;
            };
        }

        return true;
    }

    @Override
    public boolean handleFault(MessageContext messageContext) throws WebServiceClientException {

        log.info("### SOAP FAULT ###");

        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            messageContext.getResponse().writeTo(buffer);
            String payload = buffer.toString(java.nio.charset.StandardCharsets.UTF_8.name());

            log.info(payload);

        } catch (IOException e) {
            throw new WebServiceClientException("Can not write the SOAP fault into the out stream", e) {
                private static final long serialVersionUID = 2005717918800166228L;
            };
        }

        return true;
    }

    @Override
    public void afterCompletion(MessageContext messageContext, Exception ex) throws WebServiceClientException {

    }
}
