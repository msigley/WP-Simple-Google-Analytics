<?php
function google_analytics_opt_out_link() {
	$WPSimpleGoogleAnalytics = WPSimpleGoogleAnalytics::object();

	ob_start();
	?>
	<p id="ga-opt-out">
		<?php if( $WPSimpleGoogleAnalytics->has_user_opted_out() ) : ?>
			<strong>You are opted out of Google Analytics tracking.</strong>
		<?php else : ?>
			<a href="<?php echo add_query_arg( 'ga_opt_out', '', $WPSimpleGoogleAnalytics->self_uri() ); ?>#ga-opt-out">Opt out of Google Analytics tracking</a>
		<?php endif; ?>
	</p>
	<?php
	$output = ob_get_contents();
	ob_end_clean();

	return $output;
}