package kz.uco.shep.api;

public interface ShepService {
	kz.uco.service.shep.channel.sync.ws.SyncSendMessageResponse sendSyncRequest(String serviceId, Object innerData, String routeId);
}
