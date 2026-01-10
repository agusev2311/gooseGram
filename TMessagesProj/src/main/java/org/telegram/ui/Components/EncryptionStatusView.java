/*
 * Encryption status view for messages
 */

package org.telegram.ui.Components;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.util.AttributeSet;
import android.view.View;

import org.telegram.messenger.AndroidUtilities;
import org.telegram.ui.ActionBar.Theme;

/**
 * View to display encryption status on messages
 */
public class EncryptionStatusView extends View {
    private Paint textPaint;
    private Paint bgPaint;
    private String status;
    private int bgColor;
    private int textColor;

    public enum Status {
        ENCRYPTED("🔐 Encrypted", 0xFF4CAF50),      // Green
        DECRYPTED("✓ Decrypted", 0xFF4CAF50),       // Green
        NOT_ENCRYPTED("Plain text", 0xFF757575),     // Gray
        DECRYPTION_FAILED("✗ Decryption failed", 0xFFf44336), // Red
        NOT_CONFIGURED("⚠ Not configured", 0xFFFF9800); // Orange

        public final String label;
        public final int color;

        Status(String label, int color) {
            this.label = label;
            this.color = color;
        }
    }

    public EncryptionStatusView(Context context) {
        super(context);
        init();
    }

    public EncryptionStatusView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }

    public EncryptionStatusView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init();
    }

    private void init() {
        textPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        textPaint.setTextSize(AndroidUtilities.dp(12));
        textPaint.setColor(0xFFFFFFFF);

        bgPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
        bgColor = 0xFF4CAF50;
        bgPaint.setColor(bgColor);

        setStatus(Status.NOT_ENCRYPTED);
    }

    public void setStatus(Status status) {
        this.status = status.label;
        this.bgColor = status.color;
        bgPaint.setColor(bgColor);
        invalidate();
    }

    public void setStatus(String statusText, int color) {
        this.status = statusText;
        this.bgColor = color;
        bgPaint.setColor(bgColor);
        invalidate();
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);

        if (status == null || status.isEmpty()) {
            return;
        }

        int padding = AndroidUtilities.dp(4);
        int height = AndroidUtilities.dp(24);

        // Draw background
        canvas.drawRoundRect(0, 0, getWidth(), height, 
                            AndroidUtilities.dp(4), AndroidUtilities.dp(4), bgPaint);

        // Draw text
        float textX = padding;
        float textY = height / 2 + textPaint.getTextSize() / 3;
        canvas.drawText(status, textX, textY, textPaint);
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int width = MeasureSpec.getSize(widthMeasureSpec);
        if (status != null && !status.isEmpty()) {
            float textWidth = textPaint.measureText(status);
            width = (int) (textWidth + AndroidUtilities.dp(12));
        }
        int height = AndroidUtilities.dp(24);
        setMeasuredDimension(width, height);
    }
}
