<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Avada Builder addon class
 * @author Webnus <info@webnus.net>
 */
class MEC_addon_avada extends MEC_base
{
    /**
     * @var MEC_factory
     */
    public $factory;

    /**
     * @var MEC_main
     */
    public $main;

    /**
     * Constructor method
     * @author Webnus <info@webnus.net>
     */
    public function __construct()
    {
        // MEC Factory class
        $this->factory = $this->getFactory();
        
        // MEC Main class
        $this->main = $this->getMain();
    }
    
    /**
     * Initialize the Elementor addon
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        $this->factory->action('fusion_builder_before_init', array($this, 'register'));
    }

    public function register()
    {
        $calendar_posts = get_posts(array('post_type'=>'mec_calendars', 'posts_per_page'=>'-1'));

        $shortcodes = [];
        foreach($calendar_posts as $calendar_post)
        {
            $shortcodes[$calendar_post->ID] = $calendar_post->post_title;
        }

        fusion_builder_map([
            'name'            => esc_attr__('MEC', 'mec'),
            'shortcode'       => 'MEC',
            'icon'            => 'fusiona-code',
            'preview'         => MEC_ABSPATH.'app/addons/avada/preview.php',
            'preview_id'      => 'mec-avada-shortcode-element',
            'allow_generator' => true,
            'params'          => [
                [
                    'type'        => 'select',
                    'heading'     => esc_attr__('Shortcode', 'mec'),
                    'description' => esc_attr__('Select one of created shortcodes.', 'mec'),
                    'param_name'  => 'id',
                    'value'       => $shortcodes,
                    'default'     => '',
                ],
            ],
        ]);
    }
}