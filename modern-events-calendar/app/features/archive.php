<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_archive extends MEC_base
{
    /**
     * Constructor method
     * @author Webnus <info@webnus.net>
     */
    public function __construct()
    {
    }
    
    /**
     * Initialize search feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        // Main
        $main = $this->getMain();

        // Settings
        $settings = $main->get_settings();

        // Sidebar Status
        $sidebar_status = (boolean) ($settings['archive_sidebar'] ?? 0);

        if($sidebar_status)
        {
            add_action( 'widgets_init', function()
            {
                register_sidebar([
                    'name'          => __( 'MEC Archive', 'mec'),
                    'id'            => 'mec-archive',
                    'description'   => __('Widgets in this area will be shown on archive pages.', 'mec'),
                    'before_widget' => '',
                    'after_widget'  => '',
                    'before_title'  => '',
                    'after_title'   => '',
                ]);
            });
        }
    }
}