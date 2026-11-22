package app.btr15.tool;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.view.View;

/** Renders the supplied 100x100 BTR15 illustration without rasterizing it. */
public final class Btr15VectorIllustration extends View {
    public static final int DISPLAY_ON_ARROW = 0;
    public static final int DISPLAY_OFF = 1;
    public static final int DISPLAY_OFF_ARROW = 2;

    // Common bounds include the device and the optional power-button arrow.
    // Every state uses the same transform, so switching variants never shifts
    // or resizes the BTR15 and the arrow cannot be clipped.
    private static final float CONTENT_LEFT = 34.35f / 100f;
    private static final float CONTENT_TOP = 10.35f / 100f;
    private static final float CONTENT_RIGHT = 85.66f / 100f;
    private static final float CONTENT_BOTTOM = 81.85f / 100f;
    private static final float DEVICE_CENTER = 50.50f / 100f;
    private static final float DISPLAY_SCALE = 1.18f;
    // Preserve the approved 420-dpi rendering on normal/wide layouts while
    // allowing the complete composition to shrink on narrow logical screens.
    private static final float MAX_VECTOR_SIDE_DP = 433.35f;
    // At the approved size, 375dp consists of the device's visible height plus
    // 64.8dp of surrounding layout space. Retain that space at every density.
    private static final float CONTAINER_OVERHEAD_DP = 64.8f;
    // 50% version: reduce the original lower gap by half, then center the
    // device between the fixed header and the raised instruction line.
    private static final float DEVICE_TOP_OFFSET_DP = 23f;

    private Drawable vector;
    private int variant;

    public Btr15VectorIllustration(Context context) {
        this(context, DISPLAY_ON_ARROW);
    }

    public Btr15VectorIllustration(Context context, int variant) {
        super(context);
        setBackgroundColor(Color.WHITE);
        this.variant = variant;
        vector = loadVector(context, variant);
        setContentDescription("BTR15 display illustration");
        setWillNotDraw(false);
    }

    public void setVariant(int variant) {
        if (this.variant == variant) {
            return;
        }
        this.variant = variant;
        vector = loadVector(getContext(), variant);
        invalidate();
    }

    /**
     * Returns a container height that preserves the approved geometry without
     * assuming a particular density or logical screen width.
     */
    public static int recommendedHeight(Context context, int availableWidthPx) {
        float density = context.getResources().getDisplayMetrics().density;
        float side = Math.min(Math.max(1, availableWidthPx) * DISPLAY_SCALE,
                MAX_VECTOR_SIDE_DP * density);
        return Math.round(side * (CONTENT_BOTTOM - CONTENT_TOP)
                + CONTAINER_OVERHEAD_DP * density);
    }

    private Drawable loadVector(Context context, int variant) {
        String name;
        switch (variant) {
            case DISPLAY_OFF:
                name = "power_cycle_display_off";
                break;
            case DISPLAY_OFF_ARROW:
                name = "power_cycle_display_off_arrow";
                break;
            default:
                name = "power_cycle_display_on_arrow";
                break;
        }
        int resourceId = context.getResources().getIdentifier(
                name, "drawable", context.getPackageName());
        return resourceId == 0 ? null : context.getResources().getDrawable(resourceId);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        if (vector == null || getWidth() <= 0 || getHeight() <= 0) {
            return;
        }

        float contentHeight = CONTENT_BOTTOM - CONTENT_TOP;
        int inset = Math.max(2, Math.round(2f
                * getResources().getDisplayMetrics().density));
        float density = getResources().getDisplayMetrics().density;
        float desiredSide = Math.min(getWidth() * DISPLAY_SCALE,
                MAX_VECTOR_SIDE_DP * density);
        float centerX = getWidth() / 2f;
        float leftLimitedSide = (centerX - inset) / (DEVICE_CENTER - CONTENT_LEFT);
        float rightLimitedSide = (getWidth() - inset - centerX)
                / (CONTENT_RIGHT - DEVICE_CENTER);
        float widthLimitedSide = Math.min(leftLimitedSide, rightLimitedSide);
        int verticalOffset = Math.round(DEVICE_TOP_OFFSET_DP * density);
        // Account for the intentional top offset when enforcing the lower
        // boundary. The former calculation omitted it and clipped at 320 dpi.
        float heightLimitedSide = (getHeight() - 2f * inset - verticalOffset)
                / contentHeight;
        int side = Math.round(Math.min(desiredSide,
                Math.min(widthLimitedSide, heightLimitedSide)));
        if (side <= 0) {
            return;
        }

        // Keep the BTR15 body itself centered. The asymmetric arrow occupies
        // spare space to its right without moving the device between states.
        int left = Math.round(centerX - side * DEVICE_CENTER);
        int top = inset + verticalOffset - Math.round(side * CONTENT_TOP);
        vector.setBounds(left, top, left + side, top + side);
        vector.draw(canvas);
    }

}
