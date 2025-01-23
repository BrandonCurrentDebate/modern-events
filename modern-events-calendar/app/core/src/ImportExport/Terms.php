<?php

namespace MEC\ImportEXport;

class Terms {

	public $taxonomy;

	function __construct( $taxonomy ){

		$this->init( $taxonomy );
	}

	public function init( $taxonomy ) {

		$this->taxonomy = $taxonomy;

		add_filter( "bulk_actions-edit-{$taxonomy}", array( $this, 'add_export_bulk_action' ) );
		add_filter( "handle_bulk_actions-edit-{$taxonomy}", array( $this, 'handle_export_data_bulk_action' ),10,3);
		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_action( 'mec_import_export_page', array( $this, 'import_page' ) );
	}

	public function admin_init() {

        $ix_action = isset($_REQUEST['mec-ix-action']) ? sanitize_text_field( $_REQUEST['mec-ix-action'] ) : '';

        if( $ix_action && in_array( $ix_action, array( 'import-start-organizers', 'import-start-speakers', 'import-start-locations' ) ) ){

            global $MEC_Import_Result;
            $MEC_Import_Result = $this->import_from_csv();
        }
    }

	public function get_columns( $taxonomy ) {

		$columns = array(
			'term_id' => __('ID', 'mec'),
			'name' => esc_html__('Name', 'mec'),
			'description' => esc_html__('Description', 'mec'),
			'thumbnail' => esc_html__('Thumbnail', 'mec'),
		);


		if(!function_exists('is_plugin_active')) {

			include_once(ABSPATH . 'wp-admin/includes/plugin.php');
		}

		$is_active_dashboard = is_plugin_active( 'mec-user-dashboard/mec-user-dashboard.php' );

		if( in_array( $taxonomy, array( 'mec_organizer', 'mec_speaker' ) ) ) {

			$columns['tel'] = esc_html__('Tel', 'mec');
			$columns['email'] = esc_html__('Email', 'mec');
			$columns['url'] = esc_html__('Page URL', 'mec');
			$columns['page_label'] = esc_html__('Page Label', 'mec');
			$columns['email'] = esc_html__('Email', 'mec');
			$columns['facebook'] = esc_html__('Facebook', 'mec');
			$columns['instagram'] = esc_html__('Instagram', 'mec');
			$columns['linkedin'] = esc_html__('Linkedin', 'mec');
			$columns['twitter'] = esc_html__('Twitter', 'mec');
			$columns['featured'] = esc_html__('Featured', 'mec');

			if( $is_active_dashboard && 'mec_organizer' == $taxonomy ) {

				$columns['mec_organizer_user'] = __( 'Organizer User ID', 'mec');
			}elseif( $is_active_dashboard && 'mec_organizer' == $taxonomy ) {

				$columns['mec_speaker_user'] = __( 'Speaker User ID', 'mec');
			}

		} elseif ( 'mec_location' === $taxonomy ) {

			$columns['address'] = esc_html__('Address', 'mec');
			$columns['opening_hour'] = esc_html__('Opening Hour', 'mec');
			$columns['latitude'] = esc_html__('Latitude', 'mec');
			$columns['longitude'] = esc_html__('Longitude', 'mec');
			$columns['url'] = esc_html__('Location Website', 'mec');
		}


		return apply_filters('mec_csv_export_terms_columns', $columns, $taxonomy);
	}

	public function add_export_bulk_action( $bulk_actions ) {

		$bulk_actions['export-csv'] = __( 'Export as CSV', 'mec-advanced-organizer' );

		return $bulk_actions;
	}

	public function handle_export_data_bulk_action($redirect_url, $action, $term_ids){

		if( 'export-csv' === $action ) {

			$taxonomy = $_REQUEST['taxonomy'] ?? '';

			$columns = $this->get_columns( $taxonomy );

			$terms = get_terms(array(
				'taxonomy' => $taxonomy,
				'hide_empty' => false,
				'term_ids' => $term_ids,
			));

			$terms_data = [];
			foreach( $terms as $term ) {

				$term_id = $term->term_id;

				$term_data = [];
				foreach( $columns as $column_id => $column_title ) {

					switch( $column_id ) {
						case 'term_id':
						case 'name':
						case 'description':

							$term_data[ $column_id ] = $term->{$column_id};
							break;
						default:

							$term_data[ $column_id ] = get_term_meta( $term_id, $column_id, true );

							break;
					}
				}

				$terms_data[ $term_id ] = $term_data;
			}

			header('Content-Type: text/csv; charset=utf-8');
			header('Content-Disposition: attachment; filename=' . $taxonomy . '-' .md5(time().mt_rand(100, 999)).'.csv');

			$output = fopen('php://output', 'w');
			fprintf( $output, chr(0xEF).chr(0xBB).chr(0xBF) );
			fputcsv( $output, $columns );

			foreach( $terms_data as $term_data ) {

				fputcsv( $output, $term_data );
			}

			die();
		}

		return $redirect_url;
	}

	public function upload_featured_image( $image_url ) {

        $attach_id = \MEC\Base::get_main()->get_attach_id($image_url);
        if(!$attach_id) {

            $upload_dir = wp_upload_dir();
            $filename = basename($image_url);

            if(wp_mkdir_p($upload_dir['path'])) $file = $upload_dir['path'].'/'.$filename;
            else $file = $upload_dir['basedir'].'/'.$filename;

            if(!file_exists($file)) {

                $image_data = \MEC\Base::get_main()->get_web_page($image_url);
                file_put_contents($file, $image_data);
            }

            $wp_filetype = wp_check_filetype($filename, null);
            $attachment = array(
                'post_mime_type' => $wp_filetype['type'],
                'post_title' => sanitize_file_name($filename),
                'post_content' => '',
                'post_status'=>'inherit'
            );

            $attach_id = wp_insert_attachment( $attachment, $file );
            require_once ABSPATH.'wp-admin/includes/image.php';

            $attach_data = wp_generate_attachment_metadata( $attach_id, $file );
            wp_update_attachment_metadata( $attach_id, $attach_data );
        }

        return $attach_id;
    }

	public function import_from_csv() {

        $nonce = (isset($_POST['_wpnonce']) ? $_POST['_wpnonce'] : '');
        if (!$nonce || !wp_verify_nonce($nonce, 'mec_import_start_upload')) {

            return;
        }

        $import_action = isset($_POST['mec-ix-action']) ? sanitize_text_field($_POST['mec-ix-action']) : '';
        if ('import-start-' . str_replace( 'mec_', '', $this->taxonomy ) . 's' !== $import_action) {

            return;
        }

		$taxonomy = $this->taxonomy;
		$columns = $this->get_columns( $taxonomy );

        $feed_file = $_FILES['feed'];

        // File is not uploaded
        if (!isset($feed_file['name']) or (isset($feed_file['name']) and trim($feed_file['name']) == '')) return array('success' => 0, 'message' => __('Please upload a CSV file.', 'mec-organizer'));

        // File name validation
        $name_ex = explode('.', $feed_file['name']);
        $name_end = end($name_ex);
        if ($name_end != 'csv') return array('success' => 0, 'message' => __('Please upload a CSV file.', 'mec-organizer'));

        // Upload the File
        $upload_dir = wp_upload_dir();

        $target_path = $upload_dir['basedir'] . '/' . basename($feed_file['name']);
        $uploaded = move_uploaded_file($feed_file['tmp_name'], $target_path);

        // Error on Upload
        if (!$uploaded) return array('success' => 0, 'message' => __("An error occurred during the file upload! Please check permissions!", 'mec-organizer'));

        if ($type = mime_content_type($target_path) and $type == 'text/x-php') {
            unlink($target_path);
            return array('success' => 0, 'message' => __("Please upload a CSV file.", 'mec-organizer'));
        }

        $field_keys = [];
        $terms = [];
        if (($h = fopen($target_path, 'r')) !== false) {

            $r = 0;
            while (($data = fgetcsv($h, 1000, ",")) !== false) {
                $r++;

                $cell_1 = $data[0];
                if ($r === 1 && !is_numeric($cell_1)){

                    $field_keys['ID'] = 0;
                    foreach( $columns as $k => $title ){

                        $id = array_search( $title, $data );
                        if(false !== $id){

                            $field_keys[$title] = $id;
                        }
                    }

                    continue;
                }

				$term = [];
				foreach( $columns as $column_id => $title ) {

					$term[ $column_id ] = $data[ $field_keys[$title] ] ?? '';
				}

				$term_id = $term['term_id'] ?? false;
                if( $term_id ){

                    $term['ID'] = $term_id;
                    $terms[$term_id] = $term;
                }else{

                    $terms[] = $term;
                }

            }

            fclose($h);

            foreach ( $terms as $term_data ) {

				$term_id = (int)($term_data['term_id'] ?? 0);
				$term_name = $term_data['term_name'] ?? '';
				$args = [];
				foreach( $term_data as $t_id => $t_data ) {

					switch( $t_id ) {
						case 'term_id':
							break;
						case 'name':
						case 'description':

							$args[ $t_id ] = $t_data;
							break;
						default:
							$meta_inputs[ $t_id ] = $t_data;

					}
				}

				if( $term_id ) {

					$r = wp_update_term( $term_id, $taxonomy, $args );
				}else{

					$r = wp_insert_term( $term_name, $taxonomy, $args );
					$term_id = $r['term_id'] ?? 0;
				}

				$featured_image = $term_data['thumbnail'] ?? '';
				if( trim($featured_image) ) {

					$file = \MEC\Base::get_main()->getFile();
					$file_name = basename($featured_image);

					$path = rtrim($upload_dir['path'], DS.' ').DS.$file_name;
					$url = rtrim($upload_dir['url'], '/ ').'/'.$file_name;

					// Download Image
					$buffer = \MEC\Base::get_main()->get_web_page($featured_image);

					$file->write( $path, $buffer );
					if( $this->upload_featured_image( $url ) ) {

						$meta_inputs['thumbnail'] = $url;
					}
				}

				if( $term_id ) {

					foreach( $meta_inputs as $meta_key => $meta_value ) {

						update_term_meta( $term_id, $meta_key, $meta_value );
					}
				}
            }
        }

        // Delete File
        unlink($target_path);

        return array('success' => (count($terms) ? 1 : 0), 'message' => (count($terms) ? __('The Organizers are imported successfully!', 'mec-organizer') : __('No Organizers found to import!', 'mec-organizer')));
    }

	public function import_page( $tab ) {

		if ( 'MEC-import' !== $tab ) {
            return;
        }

		$tax = str_replace( 'mec_', '', $this->taxonomy );
		$taxonomy = "{$tax}s";

        $ix_action = isset($_REQUEST['mec-ix-action']) ? sanitize_text_field( $_REQUEST['mec-ix-action'] ) : '';
        ?>
        <div class="mec-import-<?php echo $taxonomy ?>s">
            <h3><?php echo sprintf(__('Import %s CSV File', 'mec-organizer'), ucfirst( $tax )); ?></h3>
            <form id="mec_import_csv_<?php echo $taxonomy ?>_form" action="<?php echo \MEC\Base::get_main()->get_full_url(); ?>" method="POST" enctype="multipart/form-data">
                <div class="mec-form-row">
                    <p>
						<?php
						echo sprintf(
							__("You can export %1s from %2s using the %3s menu in source website. You need a CSV export and then you're able to simply import it using this form in to your target website.", 'mec-organizer'),
							ucfirst( $taxonomy ),
							ucfirst( $tax ),
							'<strong>' . __('Modern Events Calendar', 'mec-organizer') . '</strong>'
						);
						?>
					</p>
                    <p style="color: red;">
						<?php
						echo sprintf(
							__("Please note that you should create (or imports) events before importing the %1s otherwise %2s won't import due to lack of data.", 'mec-organizer'),
							ucfirst( $taxonomy ),
							ucfirst( $tax )
						);
						?>
					</p>
                </div>
                <div class="mec-form-row">
                    <input type="file" name="feed" id="feed" title="<?php esc_attr_e('CSV File', 'mec-organizer'); ?>">
                    <input type="hidden" name="mec-ix-action" value="import-start-<?php echo $taxonomy ?>">
                    <?php wp_nonce_field('mec_import_start_upload'); ?>
                    <button class="button button-primary mec-button-primary mec-btn-2"><?php _e('Upload & Import', 'mec-organizer'); ?></button>
                </div>
            </form>
        </div>

        <?php if( $ix_action == 'import-start-' . $taxonomy ):

            global $MEC_Import_Result;
            ?>
            <div class="mec-ix-import-started">
                <?php if($MEC_Import_Result['success'] == 0): ?>
                <div class="mec-error"><?php echo $MEC_Import_Result['message']; ?></div>
                <?php else: ?>
                <div class="mec-success"><?php echo $MEC_Import_Result['message']; ?></div>
                <?php endif; ?>
            </div>
        <?php endif;
	}
}
