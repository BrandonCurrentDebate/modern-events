<?php
/*
Template Name: MEC Certificate Template
*/
global $post;
?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="X-UA-Compatible" content="ie=edge">
	<title><?php echo esc_html($post->post_title); ?></title>
	<?php wp_head(); ?>
	<style>
		@media print {
			@page {
				margin: 0;
			}

			* {
				-webkit-print-color-adjust: exact !important;
				color-adjust: exact !important;
				print-color-adjust: exact !important;
			}

			.mec-print-button {
				display: none;
			}
		}

		html, body {
			margin: 0 !important;
			padding: 0 !important;
		}

		body {
			position: relative;
		}

		#wpadminbar {
			display: none;
		}

		.mec-print-button {
			position: absolute;
			top: 20px;
			right: 20px;
			z-index: 10;
		}
	</style>
</head>
<body>
	<div class="mec-print-button"><button onclick="window.print();"><?php esc_html_e('Print Certificate', 'mec'); ?></button></div>
	<div class="mec-cert-wrapper">
		<?php the_content(); ?>
	</div>
	<?php wp_footer(); ?>
</body>
</html>
