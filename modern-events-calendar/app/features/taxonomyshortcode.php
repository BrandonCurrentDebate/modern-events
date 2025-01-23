<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Taxonomy Shortcode class.
 * @author Webnus <info@webnus.net>
 */
class MEC_feature_taxonomyshortcode extends MEC_base
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
        // Import MEC Factory
        $this->factory = $this->getFactory();

        // Import MEC Main
        $this->main = $this->getMain();
    }

    /**
     * Initialize User Events Feature
     * @author Webnus <info@webnus.net>
     */
    public function init()
    {
        // User Events Shortcode
        $this->factory->shortcode('MEC_taxonomy_category', array($this, 'category'));
    }

    public function category(): string
    {
        $categories = get_terms([
            'taxonomy' => 'mec_category'
        ]);

        return $this->output($categories);
    }

    /**
     * Show Terms Output
     *
     * @param array $terms
     * @return string
     */
    public function output(array $terms = []): string
    {
        $path = MEC::import('app.features.taxonomies.shortcode', true, true);

        ob_start();
        include $path;
        return ob_get_clean();
    }
}