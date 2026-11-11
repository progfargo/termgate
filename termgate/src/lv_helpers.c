/* Small helpers for LVGL fields Zig cannot reach.
 * lv_font_t has bit fields and translates to an opaque type,
 * so its fallback field is set here. */
#include "lvgl.h"

/* Fallback font for characters the TTF lacks (LV_SYMBOL_* icons) */
void termgate_font_set_fallback(lv_font_t * font, const lv_font_t * fallback)
{
    font->fallback = fallback;
}

/* Is the object a text area? (text input on focus) */
bool termgate_is_textarea(const lv_obj_t * obj)
{
    return obj != NULL && lv_obj_check_type(obj, &lv_textarea_class);
}

static void termgate_set_x(void * obj, int32_t v)
{
    lv_obj_set_x((lv_obj_t *)obj, v);
}

/* Slides an object horizontally from `from` to `to` (lv_anim_t has bit fields
 * and is opaque to Zig). duration 0 sets the end position at once. */
void termgate_slide_x(lv_obj_t * obj, int32_t from, int32_t to, uint32_t duration)
{
    if (duration == 0) {
        lv_obj_set_x(obj, to);
        return;
    }
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, obj);
    lv_anim_set_values(&a, from, to);
    lv_anim_set_duration(&a, duration);
    lv_anim_set_exec_cb(&a, termgate_set_x);
    lv_anim_set_path_cb(&a, lv_anim_path_ease_out);
    lv_anim_start(&a);
}

static void termgate_set_w(void * obj, int32_t v)
{
    lv_obj_set_width((lv_obj_t *)obj, v);
}

/* Changes an object's width from `from` to `to` the same way: the menu
 * slides in beside the page, which gets narrower. */
void termgate_slide_w(lv_obj_t * obj, int32_t from, int32_t to, uint32_t duration)
{
    if (duration == 0) {
        lv_obj_set_width(obj, to);
        return;
    }
    lv_anim_t a;
    lv_anim_init(&a);
    lv_anim_set_var(&a, obj);
    lv_anim_set_values(&a, from, to);
    lv_anim_set_duration(&a, duration);
    lv_anim_set_exec_cb(&a, termgate_set_w);
    lv_anim_set_path_cb(&a, lv_anim_path_ease_out);
    lv_anim_start(&a);
}

/* Drawing a terminal screen (lv_draw_*_dsc_t have bit fields) */

/* A filled rectangle, e.g. a cell run's background or the cursor */
void termgate_draw_fill(lv_layer_t * layer, int32_t x, int32_t y, int32_t w, int32_t h, uint32_t rgb, uint8_t opa)
{
    lv_draw_rect_dsc_t d;
    lv_draw_rect_dsc_init(&d);
    d.bg_color = lv_color_hex(rgb);
    d.bg_opa = opa;
    lv_area_t a = { x, y, x + w - 1, y + h - 1 };
    lv_draw_rect(layer, &d, &a);
}

/* One line of text at x/y, not wrapped; the text is copied */
void termgate_draw_text(lv_layer_t * layer, const lv_font_t * font, int32_t x, int32_t y, int32_t w, int32_t h,
                        uint32_t rgb, bool underline, const char * text)
{
    lv_draw_label_dsc_t d;
    lv_draw_label_dsc_init(&d);
    d.font = font;
    d.color = lv_color_hex(rgb);
    d.text = text;
    d.text_local = 1;
    d.flag = LV_TEXT_FLAG_EXPAND;
    d.decor = underline ? LV_TEXT_DECOR_UNDERLINE : LV_TEXT_DECOR_NONE;
    lv_area_t a = { x, y, x + w - 1, y + h - 1 };
    lv_draw_label(layer, &d, &a);
}
