<?php
/** no direct access **/
defined('MECEXEC') or die();
wp_enqueue_style('mec-lity-style');
wp_enqueue_script('mec-lity-script');
?>
<div id="webnus-dashboard" class="wrap about-wrap mec-addons">
    <div class="welcome-head w-clearfix">
        <div class="w-row">
            <div class="w-col-sm-9">
                <h1> <?php echo esc_html__('Addons', 'mec'); ?> </h1>
            </div>
            <div class="w-col-sm-3">
                <?php $styling = $this->main->get_styling(); $darkadmin_mode = ( isset($styling['dark_mode']) ) ? $styling['dark_mode'] : ''; if ($darkadmin_mode == 1): $darklogo = plugin_dir_url(__FILE__ ) . '../../../assets/img/mec-logo-w2.png'; else: $darklogo = plugin_dir_url(__FILE__ ) . '../../../assets/img/mec-logo-w.png'; endif; ?>
                <img src="<?php echo esc_url($darklogo); ?>" />
                <span class="w-theme-version"><?php echo esc_html__('Version', 'mec'); ?> <?php echo MEC_VERSION; ?></span>
            </div>
        </div>
    </div>
    <div class="welcome-content w-clearfix extra">
    <?php if(current_user_can('read')): ?>
        <?php
        $data_url = 'https://files.webnus.site/addons-api/addons-api.json';
		if (ini_get('allow_url_fopen')) {
			$body = @file_get_contents(plugin_dir_path(__FILE__ ).'../../api/addons-api/addons-api.json');
		}
        $obj = json_decode($body);
        ?>
        <div class="w-row">
        <?php if ( !empty( $obj ) ) :  ?>
        <?php foreach ($obj as $key => $value) : ?>
            <div class="w-col-sm-3">
                <div class="w-box addon">
                    <div class="w-box-child mec-addon-box">
                        <div class="mec-addon-box-head">
                            <div class="mec-addon-box-title"><img src="<?php echo plugin_dir_url(__FILE__ ).'../../api/addons-api/' . esc_html__($value->img); ?>" /><span><?php esc_html_e($value->name); ?></span></div>
                            <?php if ( $value->comingsoon == 'false' ) : ?>
                                <?php if ( $value->pro == 'true' ) : ?>
                                    <div class="mec-addon-box-pro">Requires Pro Version</div>
                                <?php else: ?>
                                    <div class="mec-addon-box-pro-lite">Requires Pro / Lite Version</div>
                                <?php endif; ?>
                            <?php endif; ?>
                        </div>
                        <div class="mec-addon-box-body">
                            <div class="mec-addon-box-content">
                                <p><?php esc_html_e($value->desc); ?></p>
                            </div>
                        </div>
                        <div class="mec-addon-box-footer">
                            <?php if ( $value->comingsoon == 'false' ) : ?>
                            <a class="mec-addon-box-intro" href="<?php esc_html_e($value->video); ?>" data-lity=""><i class="mec-sl-control-play"></i><div class="wn-p-t-right"><div class="wn-p-t-text-content"><h5>Introduction Video</h5>Watch to learn more about the features</div><i></i></div></a>
                            <a class="mec-addon-box-purchase" href="<?php esc_html_e($value->page); ?>" target="_blank"><i class="mec-sl-link"></i><div class="wn-p-t-right"><div class="wn-p-t-text-content"><h5>Details</h5>Learn everything about this addon</div><i></i></div></a>
                            <a class="mec-addon-box-purchase" href="<?php esc_html_e($value->purchase); ?>" target="_blank"><i class="mec-sl-basket"></i><div class="wn-p-t-right"><div class="wn-p-t-text-content"><h5>Add To Cart</h5>Add to cart and continue purchasing</div><i></i></div></a>
                            <?php else : ?>
                            <div class="mec-addon-box-comingsoon"><?php esc_html_e('Coming Soon', 'mec'); ?></div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
        <?php else: ?>
            <div class="w-col-sm-12">
                <div class="addons-page-error">
                    <p>
                    <?php echo esc_html__( '<strong>"file_get_contents"</strong> and <strong>"Curl"</strong> functions are <strong>not activated</strong> on your server. Please contact your host provider in this regard.', 'mec'); ?>
                    </p>
                </div>
            </div>
        <?php endif; ?>
        </div>
    <?php endif; ?>
    </div>
</div>