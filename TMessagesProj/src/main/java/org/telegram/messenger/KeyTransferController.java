package org.telegram.messenger;

import android.os.Handler;
import android.text.TextUtils;

import org.telegram.ui.Components.BulletinFactory;

import java.util.ArrayList;
import java.util.HashSet;

public class KeyTransferController implements NotificationCenter.NotificationCenterDelegate {
    private static volatile KeyTransferController[] Instance = new KeyTransferController[UserConfig.MAX_ACCOUNT_COUNT];

    public static KeyTransferController getInstance(int account) {
        KeyTransferController localInstance = Instance[account];
        if (localInstance == null) {
            synchronized (KeyTransferController.class) {
                localInstance = Instance[account];
                if (localInstance == null) {
                    Instance[account] = localInstance = new KeyTransferController(account);
                }
            }
        }
        localInstance.ensureInitialized();
        return localInstance;
    }

    private final int currentAccount;
    private final HashSet<Integer> processedAckIds = new HashSet<>();
    private volatile boolean initialized;

    private KeyTransferController(int account) {
        currentAccount = account;
    }

    private void initializeOnUiThread() {
        synchronized (this) {
            if (initialized) {
                return;
            }
            initialized = true;
        }
        NotificationCenter.getInstance(currentAccount).addObserver(this, NotificationCenter.didReceiveNewMessages);
    }

    private void ensureInitialized() {
        if (initialized) {
            return;
        }
        Handler handler = ApplicationLoader.applicationHandler;
        if (handler == null) {
            return;
        }
        if (Thread.currentThread() == handler.getLooper().getThread()) {
            initializeOnUiThread();
        } else {
            handler.post(this::initializeOnUiThread);
        }
    }

    @SuppressWarnings("unchecked")
    @Override
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id != NotificationCenter.didReceiveNewMessages || args == null || args.length < 3) {
            return;
        }
        if (!(args[0] instanceof Long) || !(args[1] instanceof ArrayList) || !(args[2] instanceof Boolean)) {
            return;
        }
        boolean scheduled = (Boolean) args[2];
        if (scheduled) {
            return;
        }
        long did = (Long) args[0];
        long selfId = UserConfig.getInstance(currentAccount).getClientUserId();
        if (selfId == 0 || did != selfId) {
            return;
        }
        ArrayList<MessageObject> messages = (ArrayList<MessageObject>) args[1];
        for (int i = 0; i < messages.size(); i++) {
            MessageObject messageObject = messages.get(i);
            if (messageObject == null || messageObject.messageOwner == null) {
                continue;
            }
            if (!processedAckIds.add(messageObject.getId())) {
                continue;
            }
            if (processedAckIds.size() > 64) {
                processedAckIds.clear();
                processedAckIds.add(messageObject.getId());
            }
            String ackText = EncryptionManager.getKeyTransferAckText(messageObject.messageOwner);
            if (TextUtils.isEmpty(ackText)) {
                continue;
            }
            AndroidUtilities.runOnUIThread(() -> BulletinFactory.global().createSimpleBulletin(R.raw.contact_check, ackText).show());
        }
    }
}
