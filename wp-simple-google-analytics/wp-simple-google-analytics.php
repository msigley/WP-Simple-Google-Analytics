<?php
/*
Plugin Name: WP Simple Google Analytics
Plugin URI: https://github.com/msigley
Description: Simple Google Analytics implementation that avoids using cookies and external javascript.
Version: 1.1.1
Author: Matthew Sigley
License: GPL2
*/

class WPSimpleGoogleAnalytics {
	private static $object = null;
	private $tracking_id = null;
	private $analytics_js_url = 'https://www.google-analytics.com/analytics.js';
	private $analytics_js = null;
	private $request_ip = null;
	private $track_internal_ips = false;
	private $do_not_track_ips = false;
	private $do_not_track_reason = false;

	private function __construct() {
		//Plugin activation/deactivation
		register_deactivation_hook( __FILE__, array($this, 'deactivation') );

		add_action( 'wp_print_styles', array( $this, 'print_analytics_js' ), 1 );

		if( defined( 'GOOGLE_ANALYTICS_TRACKING_ID' ) )
			$this->tracking_id = GOOGLE_ANALYTICS_TRACKING_ID;
		
		if( empty( $this->tracking_id ) || is_admin() ) {
			$this->do_not_track_reason = 'Missing tracking id.';
			return;
		}

		if( is_admin() ) {
			$this->do_not_track_reason = 'In admin area or responding to an ajax request.';
			return;
		}

		if( defined( 'GOOGLE_ANALYTICS_DEBUG' ) && !empty( GOOGLE_ANALYTICS_DEBUG ) )
			$this->analytics_js_url = 'https://www.google-analytics.com/analytics_debug.js';

		if( defined( 'GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS' ) )
			$this->track_internal_ips = !empty( GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS );

		$ip = $_SERVER['REMOTE_ADDR'];
		if( $this->track_internal_ips )
			$ip = (string) filter_var( $ip, FILTER_VALIDATE_IP );
		else
			$ip = (string) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		$this->request_ip = @inet_pton( $ip );

		if( empty( $this->request_ip ) ) {
			$this->do_not_track_reason = 'Invalid or internal IP address.';
			return;
		}

		if( defined( 'GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS' ) && !empty( GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS ) ) {
			$do_not_track_ips_cache_key = GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS;
			if( is_array( $do_not_track_ips ) ) // Support serialized arrays for PHP 5.6
				$do_not_track_ips_cache_key = serialize( $do_not_track_ips );

			// Try to pull the whitelisted ips array from the cache to avoid building it on every request
			$do_not_track_ips = wp_cache_get( $do_not_track_ips_cache_key, 'wp_simple_google_analytics_do_not_track_ips' );
			if( false === $do_not_track_ips ) {
				// Build whitelisted ips array
				$do_not_track_ips = GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS;
				if( !is_array( $do_not_track_ips ) )
					$do_not_track_ips = unserialize( $do_not_track_ips ); 
				foreach( $do_not_track_ips as &$do_not_track_ip ) {
					$slash_pos = strrpos( $do_not_track_ip, '/' );
					$netmask = false;
					if( false !== $slash_pos ) {
						$netmask = (int) substr( $do_not_track_ip, $slash_pos + 1 );
						$do_not_track_ip = substr( $do_not_track_ip, 0, $slash_pos );
					}

					$ip = @inet_pton( $do_not_track_ip );
					if( empty($ip) )
						continue;
					
					$ip_len = strlen( $ip );

					$do_not_track_ip = array(
						'ip' => $ip,
						'ip_len' => $ip_len
					);

					if( false !== $netmask ) {
						// Convert subnet to binary string of $bits length
						$subnet_binary = unpack( 'H*', $ip ); // Subnet in Hex
						foreach( $subnet_binary as $i => $h ) $subnet_binary[$i] = base_convert($h, 16, 2); // Array of Binary
						$subnet_binary = implode( '', $subnet_binary ); // Subnet in Binary
						
						$do_not_track_ip['subnet_binary'] = $subnet_binary;
						$do_not_track_ip['netmask'] = $netmask;
					}
				}
				wp_cache_set( $do_not_track_ips_cache_key, $do_not_track_ips, 'wp_simple_google_analytics_do_not_track_ips', DAY_IN_SECONDS );
			}

			// Check if request ip should not be tracked
			$request_ip_len = strlen( $this->request_ip );
			$request_ip_binary = unpack( 'H*', $this->request_ip ); // Subnet in Hex
			foreach( $request_ip_binary as $i => $h ) $request_ip_binary[$i] = base_convert($h, 16, 2); // Array of Binary
			$request_ip_binary = implode( '', $request_ip_binary ); // Subnet in Binary, only network bits
			$do_not_track = false;

			foreach( $do_not_track_ips as $do_not_track_ip ) {
				if( $request_ip_len != $do_not_track_ip['ip_len'] ) // Don't compare IPv4 to IPv6 addresses and vice versa
					continue;

				if( $this->request_ip == $do_not_track_ip['ip'] ) {
					$do_not_track = true;
					break;
				}
				
				if( !empty( $do_not_track_ip['netmask'] ) && !empty( $do_not_track_ip['subnet_binary'] )
					&& 0 === substr_compare( $request_ip_binary, $do_not_track_ip['subnet_binary'], 0, $do_not_track_ip['netmask'] ) ) {
					$do_not_track = true;
					break;
				}
			}

			if( $do_not_track ) {
				$this->do_not_track_reason = "This IP address is set to not be tracked.";
				return; // Do nothing id this is not to be tracked
			}
		}

		$this->analytics_js = $this->get_analytics_js();
	}
	
	static function &object() {
		if ( ! self::$object instanceof WPSimpleGoogleAnalytics ) {
			self::$object = new WPSimpleGoogleAnalytics();
		}
		return self::$object;
	}

	public function deactivation() {
		wp_cache_flush();
	}

	private function get_analytics_js() {
		$analytics_js = wp_cache_get( $this->analytics_js_url, 'wp_simple_google_analytics_js' );
		if( empty( $analytics_js ) ) {
			$response = wp_remote_get( $this->analytics_js_url );
			if( is_wp_error( $response ) )
				return false;
			
			$response_code = wp_remote_retrieve_response_code( $response );
			if( 200 != $response_code )
				return false;
			
			$analytics_js = wp_remote_retrieve_body( $response );
			wp_cache_set( $this->analytics_js_url, $analytics_js, 'wp_simple_google_analytics_js', DAY_IN_SECONDS );
		}
		return $analytics_js;
	}

	public function print_analytics_js() {
		if( current_user_can( 'edit_posts' ) )
			$this->do_not_track_reason = 'Current user can edit posts.';

		if( !empty( $this->do_not_track_reason ) ) {
			?>
			<!-- Google Analytics. Not tracking. <?php echo $this->do_not_track_reason; ?> -->
			<?php
			return;
		}
		?>
		<!-- Google Analytics -->
		<script>
			window.GoogleAnalyticsObject = 'googleAnalytics';
			window.googleAnalytics=window.googleAnalytics||function(){(googleAnalytics.q=googleAnalytics.q||[]).push(arguments)};googleAnalytics.l=+new Date;
			
			var localStorageAvailable = false;
			try {
				var storage = window['localStorage'],
					x = '__storage_test__';
				storage.setItem(x, x);
				storage.removeItem(x);
				localStorageAvailable = true;
			}
			catch(e) { }

			if( localStorageAvailable ) {
				googleAnalytics('create', {
					'trackingId': '<?php echo $this->tracking_id; ?>',
					'storage': 'none',
					'storeGac': false,
					'clientId': localStorage.getItem('ga:clientId'),
					'siteSpeedSampleRate': 10
				});
				googleAnalytics(function(tracker) {
					localStorage.setItem('ga:clientId', tracker.get('clientId'));
				});
			} else {
				googleAnalytics('create', {
					'trackingId': '<?php echo $this->tracking_id; ?>',
					'cookieDomain': '<?php echo $_SERVER['HTTP_HOST']; ?>',
					'storeGac': false,
					'siteSpeedSampleRate': 10
				});
			}

			<?php
			if( $user_id = get_current_user_id() ) :
				?>
				googleAnalytics('set', 'userId', '<?php echo md5( $user_id ); ?>');
				<?php
			endif;
			?>

			googleAnalytics('set', 'anonymizeIp', true);
			googleAnalytics('set', 'allowAdFeatures', false);
			googleAnalytics('set', 'forceSSL', true);
			googleAnalytics('set', 'transport', 'beacon');
			googleAnalytics('send', 'pageview');
		</script>
		<?php
		if( !empty( $this->analytics_js ) ) :
			?>
			<!-- <?php echo $this->analytics_js_url; ?> -->
			<script>
				<?php echo $this->analytics_js; ?>
			</script>
			<?php
		else :
			?>
			<script async src="<?php echo $this->analytics_js_url; ?>"></script>
			<?php
		endif;
		?>
		<!-- End Google Analytics -->
		<?php
	}
}

$WPSimpleGoogleAnalytics = WPSimpleGoogleAnalytics::object();
