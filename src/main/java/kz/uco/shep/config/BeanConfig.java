package kz.uco.shep.config;

import kz.uco.shep.impl.ShepServiceAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.transport.http.HttpComponentsMessageSender;

@Configuration
public class BeanConfig {
    private static final Logger log = LoggerFactory.getLogger(BeanConfig.class);

    @Bean
    public Jaxb2Marshaller marshaller() {
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        String[] packagesToScan = {
                "kz.uco.service.shep.channel.sync.ws"
        };
        marshaller.setPackagesToScan(packagesToScan);
        return marshaller;
    }

    @Bean
    public ShepServiceAdapter soapConnector(Jaxb2Marshaller marshaller) {
        ShepServiceAdapter client = new ShepServiceAdapter();
        client.setDefaultUri("https://shep.egov.kz:19023/bip-external-sync/");
        client.setMarshaller(marshaller);
        client.setUnmarshaller(marshaller);
        client.setInterceptors(new ClientInterceptor[]{
                new SoapInterceptor()
        });
        HttpComponentsMessageSender messageSender = new HttpComponentsMessageSender();
        messageSender.setConnectionTimeout(60000);
        messageSender.setReadTimeout(60000);
        client.setMessageSender(messageSender);
        return client;
    }

}
