<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var WP_Post $post */
/** @var MEC_feature_mec $this */

$icons = get_post_meta($post->ID, 'mec_icons', true);
if(!is_array($icons)) $icons = [];
?>
<div class="mec-calendar-metabox">
    <p class="info-msg"><?php esc_html_e('You can change the default icons using folloding options.', 'mec'); ?></p>
    <?php $this->main->icons()->form(
        'shortcode',
        'mec',
        $icons
    ); ?>
</div>