<?php
/** no direct access **/
defined('MECEXEC') or die();

/**
 * Webnus MEC Walker class.
 * @author Webnus <info@webnus.net>
 */
class MEC_walker extends Walker
{
    public $tree_type = 'category';
    public $db_fields = [
        'parent' => 'parent',
        'id'     => 'term_id',
    ];

    public $mec_id = [];
    public $mec_include = [];
    public $mec_exclude = [];

    /**
     * Constructor method
     * @param array $params
     * @author Webnus <info@webnus.net>
     */
    public function __construct($params = [])
    {
        $this->mec_id = $params['id'] ?? '';
        $this->mec_include = $params['include'] ?? [];
        $this->mec_exclude = $params['exclude'] ?? [];
    }

    /**
     * Starts the list before the elements are added.
     *
     * @see Walker:start_lvl()
     *
     * @since 2.5.1
     *
     * @param string $output Used to append additional content (passed by reference).
     * @param int    $depth  Depth of category. Used for tab indentation.
     * @param array  $args   An array of arguments. @see wp_terms_checklist()
     */
    public function start_lvl(&$output, $depth = 0, $args = array())
    {
        $indent  = str_repeat("\t", $depth);
        $output .= "$indent<ul class='children'>\n";
    }

    /**
     * Ends the list of after the elements are added.
     *
     * @see Walker::end_lvl()
     *
     * @since 2.5.1
     *
     * @param string $output Used to append additional content (passed by reference).
     * @param int    $depth  Depth of category. Used for tab indentation.
     * @param array  $args   An array of arguments. @see wp_terms_checklist()
     */
    public function end_lvl(&$output, $depth = 0, $args = array())
    {
        $indent  = str_repeat("\t", $depth);
        $output .= "$indent</ul>\n";
    }

    /**
     * Start the element output.
     *
     * @see Walker::start_el()
     *
     * @since 2.5.1
     *
     * @param string  $output   Used to append additional content (passed by reference).
     * @param WP_Term $data_object The current term object.
     * @param int     $depth    Depth of the term in reference to parents. Default 0.
     * @param array   $args     An array of arguments. @see wp_terms_checklist()
     * @param int     $current_object_id       ID of the current term.
     */
    public function start_el(&$output, $data_object, $depth = 0, $args = array(), $current_object_id = 0)
    {
        // Term is not Included
        if(is_array($this->mec_include) and count($this->mec_include) and !in_array($data_object->term_id, $this->mec_include)) return;

        // Term is Excluded
        if(is_array($this->mec_exclude) and count($this->mec_exclude) and in_array($data_object->term_id, $this->mec_exclude)) return;

        if(empty($args['taxonomy'])) $taxonomy = 'category';
        else $taxonomy = $args['taxonomy'];

        $args['popular_cats'] = !empty($args['popular_cats']) ? array_map('intval', $args['popular_cats']) : [];
        $class = in_array($data_object->term_id, $args['popular_cats'], true) ? ' class="popular-category"' : '';
        $args['selected_cats'] = !empty($args['selected_cats']) ? array_map('intval', $args['selected_cats']) : [];

        $is_selected = in_array($data_object->term_id, $args['selected_cats'], true);
        $selected = selected( $is_selected, true, false );

        $output .= "\n<option value='$data_object->term_id' id='$taxonomy-$this->mec_id-$data_object->term_id'$class $selected >" .
            esc_html__(apply_filters('the_category', $data_object->name, '', '')) . '</option>';
    }

    /**
     * Ends the element output, if needed.
     *
     * @param string  $output   Used to append additional content (passed by reference).
     * @param WP_Term $data_object The current term object.
     * @param int     $depth Depth of the term in reference to parents. Default 0.
     * @param array   $args     An array of arguments.
     * @see Walker::end_el()
     *
     * @since 2.5.1
     *
     * @see wp_terms_checklist()
     */
    public function end_el(&$output, $data_object, $depth = 0, $args = array())
    {
        $output .= "";
    }

    /**
     * @param WP_Term $element
     * @param $children_elements
     * @param $max_depth
     * @param $depth
     * @param $args
     * @param $output
     * @return void
     */
    public function display_element( $element, &$children_elements, $max_depth, $depth, $args, &$output )
    {
        if (!$element) {
            return;
        }

        $id_field = $this->db_fields['id'];
        $id = $element->$id_field;

        // Display this element.
        $this->has_children = ! empty( $children_elements[ $id ] );
        if ( isset( $args[0] ) && is_array( $args[0] ) ) {
            $args[0]['has_children'] = $this->has_children; // Back-compat.
        }

        $this->start_el( $output, $element, $depth, ...array_values( $args ) );

        // End this element.
        $this->end_el( $output, $element, $depth, ...array_values( $args ) );
    }

    public function walk( $elements, $max_depth, ...$args )
    {
        $output = '<select multiple="multiple">';

        // Invalid parameter or nothing to walk.
        if ( $max_depth < -1 || empty( $elements ) ) {
            return $output;
        }

        foreach ( $elements as $e ) {
            $this->display_element( $e, $empty_array, 1, 0, $args, $output );
        }

        $output .= '</select>';
        return $output;
    }
}