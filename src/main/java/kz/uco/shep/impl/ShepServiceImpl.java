package kz.uco.shep.impl;

import kz.uco.service.shep.channel.sync.ws.*;
import kz.uco.shep.api.ShepService;
import kz.uco.shep.utils.XMLSignUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.UUID;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

@Service
public class ShepServiceImpl implements ShepService {

    private static final Logger LOGGER = LoggerFactory.getLogger(ShepServiceImpl.class);

    @Autowired
    ShepServiceAdapter shepServiceAdapter;

    @Override
    public SyncSendMessageResponse sendSyncRequest(String serviceId, Object innerData, String routeId) {
        LOGGER.info("Shep send request to serviceId: " + serviceId);
        ObjectFactory objectFactory = new ObjectFactory();
        SendMessage sendMessage = objectFactory.createSendMessage();
        SyncSendMessageRequest request = new SyncSendMessageRequest();

        // Информация о сообщении
        SyncMessageInfo messageInfo = new SyncMessageInfo();

        // Информация об отправителе
        SenderInfo senderInfo = new SenderInfo();
        senderInfo.setSenderId("enbek-contract-ws-service");
        senderInfo.setPassword("password");
        messageInfo.setSender(senderInfo);
        messageInfo.setMessageId(UUID.randomUUID().toString());
        messageInfo.setMessageDate(XMLSignUtils.dateToCalendar(new Date()));
        messageInfo.setServiceId(serviceId);
        if (nonNull(routeId) && !routeId.equals("")) {
            messageInfo.setRouteId(routeId);
        }
        request.setRequestInfo(messageInfo);

        // Бизнес-данные запроса
        RequestData data = new RequestData();
        data.setData(innerData);
        request.setRequestData(data);
        sendMessage.setRequest(request);

        SendMessageResponse response = shepServiceAdapter.sendMessage(sendMessage);

        if (isNull(response)) {
            return null;
        }
        return response.getResponse();
    }

}
