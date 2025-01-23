<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var MEC_main $main */

$main = MEC::getInstance('app.libraries.main');
$settings = $main->get_settings();

$title_tag = isset($settings['archive_title_tag']) && trim($settings['archive_title_tag']) ? $settings['archive_title_tag'] : 'h1';

/**
 * The Template for displaying events archives
 * 
 * @author Webnus <info@webnus.net>
 * @package MEC/Templates
 * @version 1.0.0
 */
get_header('mec'); ?>

    <section id="<?php echo apply_filters('mec_archive_page_html_id', 'main-content'); ?>" class="<?php echo apply_filters('mec_archive_page_html_class', 'mec-container'); ?>">
        <?php do_action('mec_before_main_content'); ?>

        <?php if(have_posts()): ?>

            <?php do_action('mec_before_events_loop'); ?>

                <?php if(have_posts()): the_post(); $title = apply_filters('mec_archive_title', get_the_title()); ?>

                    <?php if(trim($title)): ?><<?php echo esc_html($title_tag); ?>><?php echo MEC_kses::element($title); ?></<?php echo esc_html($title_tag); ?>><?php endif; ?>

                    <?php if(is_active_sidebar('mec-archive')): ?>
                    <div class="mec-archive-wrapper mec-wrap">
                        <div class="mec-archive-content col-md-8">
                            <?php the_content(); ?>
                        </div>
                        <div class="mec-archive-sidebar col-md-4">
                            <?php dynamic_sidebar('mec-archive'); ?>
                        </div>
                    </div>
                    <?php else: ?>
                    <?php the_content(); ?>
                    <?php endif; ?>

                <?php endif; // end of the loop. ?>

            <?php do_action('mec_after_events_loop'); ?>

        <?php else: ?>

        <p><?php $main->display_not_found_message(); ?></p>

        <?php endif; ?>
    </section>

    <?php do_action('mec_after_main_content'); ?>

<?php get_footer('mec');