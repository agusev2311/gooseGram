/*
 * Encryption settings activity
 */

package org.telegram.ui;

import android.content.Context;
import android.content.DialogInterface;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.Toast;

import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.messenger.ApplicationLoader;
import org.telegram.messenger.LocaleController;
import org.telegram.messenger.R;
import org.telegram.messenger.encryption.EncryptionManager;
import org.telegram.messenger.encryption.EncryptionSettings;
import org.telegram.ui.ActionBar.ActionBar;
import org.telegram.ui.ActionBar.AlertDialog;
import org.telegram.ui.ActionBar.BaseFragment;
import org.telegram.ui.ActionBar.Theme;
import org.telegram.ui.ActionBar.ThemeDescription;
import org.telegram.ui.Cells.HeaderCell;
import org.telegram.ui.Cells.TextCell;
import org.telegram.ui.Cells.TextSettingsCell;
import org.telegram.ui.Cells.EditTextSettingsCell;
import org.telegram.ui.Components.LayoutHelper;
import org.telegram.ui.Components.RecyclerListView;

import java.util.ArrayList;

/**
 * Encryption settings activity for registration and verification
 */
public class EncryptionSettingsActivity extends BaseFragment {
    private RecyclerListView listView;
    private ListAdapter listAdapter;
    private EncryptionManager encryptionManager;
    private EncryptionSettings encryptionSettings;

    private static final int SECTION_ENCRYPTION = 0;
    private static final int ROW_HEADER = 1;
    private static final int ROW_SERVER_IP = 2;
    private static final int ROW_REGISTER = 3;
    private static final int ROW_VERIFY = 4;
    private static final int ROW_STATUS = 5;
    private static final int ROW_UNREGISTER = 6;
    private static final int ROWS_COUNT = 7;

    @Override
    public boolean onFragmentCreate() {
        encryptionManager = EncryptionManager.getInstance(ApplicationLoader.applicationContext);
        encryptionSettings = encryptionManager.getSettings();
        return super.onFragmentCreate();
    }

    @Override
    public View createView(Context context) {
        actionBar.setTitle("End-to-End Encryption");
        actionBar.setBackButtonImage(R.drawable.ic_ab_back);
        actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() {
            @Override
            public void onItemClick(int id) {
                if (id == -1) {
                    finishFragment();
                }
            }
        });

        FrameLayout frameLayout = new FrameLayout(context);
        frameLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));

        listView = new RecyclerListView(context);
        listView.setLayoutManager(new LinearLayoutManager(context, LinearLayoutManager.VERTICAL, false));
        listView.setAdapter(listAdapter = new ListAdapter(context));
        frameLayout.addView(listView, LayoutHelper.createFrame(LayoutHelper.MATCH_PARENT, LayoutHelper.MATCH_PARENT));

        return fragmentView = frameLayout;
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private Context mContext;

        ListAdapter(Context context) {
            mContext = context;
        }

        @Override
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            return holder.getItemViewType() != 0;
        }

        @Override
        public int getItemCount() {
            return ROWS_COUNT;
        }

        @Override
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            switch (viewType) {
                case 1: // Header
                    return new RecyclerListView.Holder(new HeaderCell(mContext));
                case 2: // Text cell
                    TextSettingsCell cell = new TextSettingsCell(mContext);
                    cell.setBackground(Theme.getSelectorDrawable(false));
                    return new RecyclerListView.Holder(cell);
                case 3: // EditText cell
                default:
                    TextSettingsCell textCell = new TextSettingsCell(mContext);
                    textCell.setBackground(Theme.getSelectorDrawable(false));
                    return new RecyclerListView.Holder(textCell);
            }
        }

        @Override
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            switch (position) {
                case ROW_HEADER: {
                    HeaderCell header = (HeaderCell) holder.itemView;
                    header.setText("Encryption Settings");
                    break;
                }
                case ROW_SERVER_IP: {
                    TextSettingsCell cell = (TextSettingsCell) holder.itemView;
                    String ip = encryptionSettings.getServerIP();
                    cell.setText("Server IP: " + (ip != null ? ip : "Not set"), false);
                    cell.setOnClickListener(v -> showServerIPDialog());
                    break;
                }
                case ROW_REGISTER: {
                    TextSettingsCell cell = (TextSettingsCell) holder.itemView;
                    String status = encryptionSettings.isRegistered() ? "✓ Registered" : "Click to register";
                    cell.setText("Register Device: " + status, false);
                    if (!encryptionSettings.isRegistered()) {
                        cell.setOnClickListener(v -> showRegistrationDialog());
                    }
                    break;
                }
                case ROW_VERIFY: {
                    TextSettingsCell cell = (TextSettingsCell) holder.itemView;
                    if (encryptionSettings.isRegistered()) {
                        String status = encryptionSettings.isVerified() ? "✓ Verified" : "Click to verify";
                        cell.setText("Verify Device: " + status, false);
                        if (!encryptionSettings.isVerified()) {
                            cell.setOnClickListener(v -> showVerificationDialog());
                        }
                    }
                    break;
                }
                case ROW_STATUS: {
                    TextSettingsCell cell = (TextSettingsCell) holder.itemView;
                    StringBuilder status = new StringBuilder();
                    status.append("Status: ");
                    if (encryptionSettings.isVerified()) {
                        status.append("✓ Active");
                    } else if (encryptionSettings.isRegistered()) {
                        status.append("⏳ Awaiting verification");
                    } else {
                        status.append("✗ Inactive");
                    }
                    cell.setText(status.toString(), false);
                    break;
                }
                case ROW_UNREGISTER: {
                    TextSettingsCell cell = (TextSettingsCell) holder.itemView;
                    if (encryptionSettings.isRegistered()) {
                        cell.setText("Unregister Device (Remove all keys)", false);
                        cell.setOnClickListener(v -> showUnregisterDialog());
                    }
                    break;
                }
            }
        }

        @Override
        public int getItemViewType(int position) {
            if (position == ROW_HEADER) {
                return 1; // Header
            }
            return 2; // Text cell
        }
    }

    private void showServerIPDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle("Set Server IP");

        final EditText input = new EditText(getParentActivity());
        input.setInputType(InputType.TYPE_TEXT_VARIATION_URI);
        input.setText(encryptionSettings.getServerIP() != null ? encryptionSettings.getServerIP() : "");
        input.setHint("192.168.1.1 or example.com:8000");

        LinearLayout container = new LinearLayout(getParentActivity());
        container.setPadding(AndroidUtilities.dp(10), AndroidUtilities.dp(10), 
                            AndroidUtilities.dp(10), AndroidUtilities.dp(10));
        container.addView(input);

        builder.setView(container);
        builder.setPositiveButton("OK", (dialog, which) -> {
            String ip = input.getText().toString().trim();
            if (!ip.isEmpty()) {
                encryptionSettings.setServerIP(ip);
                listAdapter.notifyDataSetChanged();
                Toast.makeText(getParentActivity(), "Server IP updated", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(getParentActivity(), "Please enter a valid IP", Toast.LENGTH_SHORT).show();
            }
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void showRegistrationDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle("Register Device");

        LinearLayout container = new LinearLayout(getParentActivity());
        container.setOrientation(LinearLayout.VERTICAL);
        container.setPadding(AndroidUtilities.dp(10), AndroidUtilities.dp(10), 
                            AndroidUtilities.dp(10), AndroidUtilities.dp(10));

        final EditText userIdInput = new EditText(getParentActivity());
        userIdInput.setInputType(InputType.TYPE_CLASS_NUMBER);
        userIdInput.setHint("Enter your User ID");
        container.addView(userIdInput);

        builder.setView(container);
        builder.setPositiveButton("Register", (dialog, which) -> {
            String userIdStr = userIdInput.getText().toString().trim();
            if (!userIdStr.isEmpty()) {
                try {
                    long userId = Long.parseLong(userIdStr);
                    String serverIP = encryptionSettings.getServerIP();
                    if (serverIP == null || serverIP.isEmpty()) {
                        Toast.makeText(getParentActivity(), "Please set server IP first", Toast.LENGTH_SHORT).show();
                    } else {
                        Toast.makeText(getParentActivity(), "Starting registration...", Toast.LENGTH_LONG).show();
                        encryptionManager.startRegistration(serverIP, userId);
                    }
                } catch (NumberFormatException e) {
                    Toast.makeText(getParentActivity(), "Invalid User ID", Toast.LENGTH_SHORT).show();
                }
            }
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void showVerificationDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle("Verify Device");
        builder.setMessage("Enter the verification code you received from the bot");

        final EditText input = new EditText(getParentActivity());
        input.setInputType(InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        input.setHint("Verification code");

        LinearLayout container = new LinearLayout(getParentActivity());
        container.setPadding(AndroidUtilities.dp(10), AndroidUtilities.dp(10), 
                            AndroidUtilities.dp(10), AndroidUtilities.dp(10));
        container.addView(input);

        builder.setView(container);
        builder.setPositiveButton("Verify", (dialog, which) -> {
            String verifyCode = input.getText().toString().trim();
            if (!verifyCode.isEmpty()) {
                Toast.makeText(getParentActivity(), "Verifying...", Toast.LENGTH_LONG).show();
                encryptionManager.verifyUser(verifyCode);
            } else {
                Toast.makeText(getParentActivity(), "Please enter verification code", Toast.LENGTH_SHORT).show();
            }
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    private void showUnregisterDialog() {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle("Unregister Device");
        builder.setMessage("Are you sure? This will delete all encryption keys. They cannot be recovered!");
        builder.setPositiveButton("Delete Keys", (dialog, which) -> {
            encryptionSettings.clearAll();
            listAdapter.notifyDataSetChanged();
            Toast.makeText(getParentActivity(), "Device unregistered", Toast.LENGTH_SHORT).show();
        });
        builder.setNegativeButton("Cancel", null);
        builder.show();
    }

    @Override
    public ArrayList<ThemeDescription> getThemeDescriptions() {
        ArrayList<ThemeDescription> themeDescriptions = new ArrayList<>();
        themeDescriptions.add(new ThemeDescription(listView, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{TextSettingsCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
        themeDescriptions.add(new ThemeDescription(listView, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, null, null, null, Theme.key_windowBackgroundWhiteGrayText2));
        return themeDescriptions;
    }
}
