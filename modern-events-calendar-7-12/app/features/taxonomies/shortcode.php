<?php
/** no direct access **/
defined('MECEXEC') or die();

/** @var WP_Term[] $terms */
?>
<div class="mec-taxonomies-shortcode">
	<ul>
		<?php foreach($terms as $term): ?>
		<?php
			$icon = get_metadata('term', $term->term_id, 'mec_cat_icon', true);
			$icon = isset($icon) && $icon != '' ? '<i class="'.esc_attr($icon).' mec-color"></i>' : '';

			$color = get_metadata('term', $term->term_id, 'mec_cat_color', true);;

			$color_html = '';
			if($color) $color_html .= '<span class="mec-event-category-color" style="--background-color: '.esc_attr($color).';background-color: '.esc_attr($color).'">&nbsp;</span>';
		?>
		<li>
			<a href="<?php echo esc_url(get_term_link($term)); ?>">
				<h4><?php echo $icon.esc_html($term->name).$color_html; ?></h4>
				<?php if(trim($term->description)): ?>
				<p><?php echo esc_html($term->description); ?></p>
				<?php endif; ?>
			</a>
		</li>
		<?php endforeach; ?>
	</ul>
</div>