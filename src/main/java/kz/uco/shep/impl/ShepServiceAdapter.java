package kz.uco.shep.impl;

import kz.uco.service.shep.channel.sync.ws.SendMessage;
import kz.uco.service.shep.channel.sync.ws.SendMessageResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ws.client.WebServiceTransportException;
import org.springframework.ws.client.core.support.WebServiceGatewaySupport;
import org.springframework.ws.soap.client.SoapFaultClientException;

public class ShepServiceAdapter extends WebServiceGatewaySupport {
    private static final Logger log = LoggerFactory.getLogger(ShepServiceAdapter.class);

    public SendMessageResponse sendMessage(SendMessage request) throws SoapFaultClientException, WebServiceTransportException {
        SendMessageResponse res = null;
        try {
            res = (SendMessageResponse) getWebServiceTemplate().marshalSendAndReceive(request);
        } catch (SoapFaultClientException | WebServiceTransportException e) {
            log.error(e.toString());
        }

        return res;
    }
}
