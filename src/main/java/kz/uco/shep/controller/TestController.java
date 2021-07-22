package kz.uco.shep.controller;

import kz.uco.service.shep.channel.sync.ws.SyncSendMessageResponse;
import kz.uco.shep.api.ShepService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestController {
    @Autowired
    ShepService shepService;

    @GetMapping(value = "/shep")
    public void getShep() {
        SyncSendMessageResponse messageResponse = shepService.sendSyncRequest("enbek-contract-ws-service", "Test", null);

        System.out.println(messageResponse.getResponseInfo().getMessageId());
    }
}
