<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Event Fields class.
 * @author Webnus <info@webnus.net>
 */
class MEC_eventFields extends MEC_base
{
    /**
     * @var MEC_main
     */
    public $main;
    public $settings;

    /**
     * Constructor method
     * @author Webnus <info@webnus.net>
     */
    public function __construct()
    {
        // Import MEC Main
        $this->main = $this->getMain();

        // MEC Settings
        $this->settings = $this->main->get_settings();
    }

    public function form($args)
    {
        if(!isset($this->settings['display_event_fields_backend']) || $this->settings['display_event_fields_backend'] != 1) return;

        $id = $args['id'] ?? 'mec-event-data';
        $class = $args['class'] ?? 'mec-meta-box-fields mec-event-tab-content';
        $data = $args['data'] ?? [];
        $name_prefix = $args['name_prefix'] ?? 'mec';
        $id_prefix = $args['id_prefix'] ?? 'mec_event_fields_';
        $mandatory_status = $args['mandatory_status'] ?? true;

        $event_fields = $this->main->get_event_fields();
        ?>
        <div class="<?php echo esc_attr($class); ?>" id="<?php echo esc_attr($id); ?>">
            <h4><?php echo esc_html__('Event Data', 'mec'); ?></h4>

            <?php foreach($event_fields as $j => $event_field): if(!is_numeric($j)) continue; ?>
                <div class="mec-form-row">

                    <div class="mec-col-4">
                        <?php
                        $event_field_name = isset($event_field['label']) ? strtolower(str_replace([' ',',',':','"',"'"], '_', $event_field['label'])) : '';
                        $value = $data[$j] ?? NULL;
                        ?>
                        <?php if(isset($event_field['label'])): ?><label for="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>"><?php esc_html_e(stripslashes($event_field['label']), 'mec'); ?><?php echo (($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) ? '<span class="wbmec-mandatory">*</span>' : ''); ?></label><?php endif; ?>
                    </div>

                    <div class="mec-col-8">
                        <?php /** Text **/ if($event_field['type'] == 'text'): ?>
                            <input id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>" type="text" name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" value="<?php echo esc_attr($value); ?>" placeholder="<?php esc_attr($event_field_name); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?> />

                        <?php /** Email **/ elseif($event_field['type'] == 'email'): ?>
                            <input id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>" type="email" name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" value="<?php echo esc_attr($value); ?>" placeholder="<?php esc_attr($event_field_name); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?> />

                        <?php /** URL **/ elseif($event_field['type'] == 'url'): ?>
                            <input id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>" type="url" name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" value="<?php echo esc_attr($value); ?>" placeholder="<?php esc_attr($event_field_name); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?> />

                        <?php /** Date **/ elseif($event_field['type'] == 'date'): ?>
                            <input id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>" class="mec-date-picker" type="text" name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" value="<?php echo esc_attr($value); ?>" placeholder="<?php esc_attr($event_field_name); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?> min="1970-01-01" max="2099-12-31" />

                        <?php /** Tel **/ elseif($event_field['type'] == 'tel'): ?>
                            <input id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>" oninput="this.value=this.value.replace(/(?![0-9])./gmi,'')" type="tel" name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" value="<?php echo esc_attr($value); ?>" placeholder="<?php esc_attr($event_field_name); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?> />

                        <?php /** Textarea **/ elseif($event_field['type'] == 'textarea' and (!isset($event_field['editor']) || !$event_field['editor'])): ?>
                            <textarea id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>" name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" placeholder="<?php esc_attr($event_field_name); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?>><?php echo esc_textarea($value); ?></textarea>

                        <?php /** Textarea (Editor) **/ elseif($event_field['type'] == 'textarea' and (isset($event_field['editor']) and $event_field['editor'])): wp_editor($value, $id_prefix.$j, array(
                            'textarea_name' => $name_prefix.'[fields]['.esc_attr($j).']',
                            'teeny' => true,
                            'media_buttons' => false,
                        )); ?>

                        <?php /** Paragraph **/ elseif($event_field['type'] == 'p'):
                            echo '<p>'.do_shortcode(stripslashes($event_field['content'])).'</p>';
                        ?>

                        <?php /** Dropdown **/ elseif($event_field['type'] == 'select'): ?>
                            <select id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j); ?>" name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" title="<?php esc_attr($event_field_name); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?>>
                                <?php if(isset($event_field['options']) and is_array($event_field['options'])): $efd = 0; foreach($event_field['options'] as $event_field_option): $efd++; ?>
                                    <option value="<?php echo (($efd == 1 and isset($event_field['ignore']) and $event_field['ignore']) ? '' : esc_attr__($event_field_option['label'], 'mec')); ?>" <?php echo ($event_field_option['label'] == $value ? 'selected="selected"' : ''); ?>><?php esc_html_e(stripslashes($event_field_option['label']), 'mec'); ?></option>
                                <?php endforeach; endif; ?>
                            </select>

                        <?php /** Radio **/ elseif($event_field['type'] == 'radio'): ?>
                            <?php $r = 0; foreach($event_field['options'] as $event_field_option): $r++; ?>
                                <label class="label-radio" for="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j.'_'.strtolower(str_replace(' ', '_', $event_field_option['label']))); ?>">
                                    <input type="radio" id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j.'_'.strtolower(str_replace(' ', '_', $event_field_option['label']))); ?>" <?php echo ($event_field_option['label'] == $value ? 'checked="checked"' : ''); ?> name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>]" value="<?php esc_html_e($event_field_option['label'], 'mec'); ?>" <?php if($mandatory_status and $r == 1 and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?> />
                                    <?php esc_html_e(stripslashes($event_field_option['label']), 'mec'); ?>
                                </label>
                            <?php endforeach; ?>

                        <?php /** Checkbox **/ elseif($event_field['type'] == 'checkbox'): ?>
                            <?php if(isset($event_field['options']) and is_array($event_field['options'])): foreach($event_field['options'] as $event_field_option): ?>
                                <label class="label-checkbox" for="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j.'_'.strtolower(str_replace(' ', '_', $event_field_option['label']))); ?>">
                                    <input type="checkbox" id="<?php echo esc_attr($id_prefix); ?><?php echo esc_attr($j.'_'.strtolower(str_replace(' ', '_', $event_field_option['label']))); ?>" <?php echo ((is_array($value) and in_array($event_field_option['label'], $value)) ? 'checked="checked"' : ''); ?> name="<?php echo esc_attr($name_prefix); ?>[fields][<?php echo esc_attr($j); ?>][]" value="<?php esc_html_e($event_field_option['label'], 'mec'); ?>" <?php if($mandatory_status and isset($event_field['mandatory']) and $event_field['mandatory']) echo 'required'; ?> />
                                    <?php esc_html_e(stripslashes($event_field_option['label']), 'mec'); ?>
                                </label>
                            <?php endforeach; endif; ?>
                        <?php endif; ?>
                    </div>

                </div>
            <?php endforeach; ?>

        </div>
        <script>
        jQuery(document).ready(function()
        {
            let requiredCheckboxes = jQuery('#<?php echo esc_attr($id); ?> :checkbox[required]');
            requiredCheckboxes.on('change', function()
            {
                let checkboxGroup = requiredCheckboxes.filter('[name="' + jQuery(this).attr('name') + '"]');
                let isChecked = checkboxGroup.is(':checked');
                checkboxGroup.prop('required', !isChecked);
            });

            requiredCheckboxes.trigger('change');
        });
        </script>
        <?php
    }
}