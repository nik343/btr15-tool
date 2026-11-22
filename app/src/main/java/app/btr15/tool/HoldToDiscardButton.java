package app.btr15.tool;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.os.SystemClock;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.widget.Button;

public final class HoldToDiscardButton extends Button {
    private static final long HOLD_MILLIS = 3_000L;

    private final Paint fill = new Paint();
    private final int border;
    private final Runnable onDiscard;
    private final Runnable advance = this::advanceHold;
    private long pressedAt = -1L;
    private float progress;

    public HoldToDiscardButton(Context context, int fillColor, int border, Runnable onDiscard) {
        super(context);
        fill.setColor(fillColor);
        this.border = border;
        this.onDiscard = onDiscard;
    }

    @Override protected void onDraw(Canvas canvas) {
        if (progress > 0f) {
            float right = border + (getWidth() - 2 * border) * progress;
            canvas.drawRect(border, border, right, getHeight() - border, fill);
        }
        super.onDraw(canvas);
    }

    @Override public boolean onTouchEvent(MotionEvent event) {
        if (!isEnabled()) {
            return false;
        }
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                startHold();
                break;
            case MotionEvent.ACTION_MOVE:
                if (event.getX() < 0 || event.getX() >= getWidth()
                        || event.getY() < 0 || event.getY() >= getHeight()) {
                    cancelHold();
                }
                break;
            case MotionEvent.ACTION_POINTER_DOWN:
            case MotionEvent.ACTION_UP:
            case MotionEvent.ACTION_CANCEL:
                cancelHold();
                break;
            default:
                break;
        }
        return true;
    }

    @Override public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (isEnabled() && isHoldKey(keyCode)) {
            if (event.getRepeatCount() == 0) {
                startHold();
            }
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    @Override public boolean onKeyUp(int keyCode, KeyEvent event) {
        if (isHoldKey(keyCode)) {
            cancelHold();
            return true;
        }
        return super.onKeyUp(keyCode, event);
    }

    private static boolean isHoldKey(int keyCode) {
        return keyCode == KeyEvent.KEYCODE_ENTER || keyCode == KeyEvent.KEYCODE_NUMPAD_ENTER
                || keyCode == KeyEvent.KEYCODE_DPAD_CENTER || keyCode == KeyEvent.KEYCODE_SPACE;
    }

    @Override public void onWindowFocusChanged(boolean focused) {
        super.onWindowFocusChanged(focused);
        if (!focused) {
            cancelHold();
        }
    }

    @Override protected void onDetachedFromWindow() {
        cancelHold();
        super.onDetachedFromWindow();
    }

    private void startHold() {
        if (pressedAt < 0L) {
            pressedAt = SystemClock.uptimeMillis();
            setPressed(true);
            postOnAnimation(advance);
        }
    }

    private void advanceHold() {
        if (pressedAt < 0L) {
            return;
        }
        if (!isShown() || !hasWindowFocus() || !isEnabled()) {
            cancelHold();
            return;
        }
        long elapsed = SystemClock.uptimeMillis() - pressedAt;
        if (elapsed >= HOLD_MILLIS) {
            cancelHold();
            onDiscard.run();
        } else {
            progress = elapsed / (float) HOLD_MILLIS;
            invalidate();
            postOnAnimation(advance);
        }
    }

    private void cancelHold() {
        removeCallbacks(advance);
        pressedAt = -1L;
        progress = 0f;
        setPressed(false);
        invalidate();
    }
}
