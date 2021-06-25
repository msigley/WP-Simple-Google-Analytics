<?php
/*
Plugin Name: WP Simple Google Analytics
Plugin URI: https://github.com/msigley
Description: Simple Google Analytics implementation that avoids using cookies and external javascript.
Version: 1.4.0
Author: Matthew Sigley
License: GPL2
*/

class WPSimpleGoogleAnalytics {
	private static $object = null;
	private $tracking_id = null;
	private $analytics_js_url = 'https://www.google-analytics.com/analytics.js';
	private $analytics_js = null;
	private $request_ip = null;
	private $request_ip_packed = null;
	private $track_internal_ips = false;
	private $do_not_track_ips = false;
	private $do_not_track_reason = false;
	private $opt_out_cookie_name = 'ga_opt_out';
	private $shortcodes = array( 'google_analytics_opt_out_link' );

	private function __construct() {
		//Plugin activation/deactivation
		register_deactivation_hook( __FILE__, array($this, 'deactivation') );

		if( defined( 'GOOGLE_ANALYTICS_TRACKING_ID' ) )
			$this->tracking_id = GOOGLE_ANALYTICS_TRACKING_ID;

		if( defined( 'GOOGLE_ANALYTICS_DEBUG' ) && !empty( GOOGLE_ANALYTICS_DEBUG ) )
			$this->analytics_js_url = 'https://www.google-analytics.com/analytics_debug.js';

		if( defined( 'GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS' ) )
			$this->track_internal_ips = !empty( GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS );

		if( defined( 'GOOGLE_ANALYTICS_TRACK_BOTS' ) )
			$this->track_bots = !empty( GOOGLE_ANALYTICS_TRACK_BOTS );

		if( defined( 'GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS' ) )
			$this->do_not_track_ips = GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS;
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

	public function init() {
		//General API
		require_once 'api.php';

		add_action( 'wp_print_styles', array( $this, 'print_analytics_js' ), 1 );

		add_action( 'init', array( $this, 'add_shortcodes' ) );

		add_filter( 'wp_headers', array( $this, 'add_referrer_policy_header' ) );

		if( empty( $this->tracking_id ) ) {
			$this->do_not_track_reason = 'Missing tracking id.';
			return;
		}

		if( is_admin() ) {
			$this->do_not_track_reason = 'In admin area or responding to an ajax request.';
			return;
		}

		if( isset( $_REQUEST['ga_opt_out'] ) ) {
			$site_url = get_option( 'siteurl' );
			$host = parse_url( $site_url, PHP_URL_HOST );
			$domain = $host;
			if( substr_count( $host, '.' ) >= 2 ) {
				$dot_pos = strrpos( $host, '.' );
				$domain = substr( $host, $dot_pos + 1 );
				$host = substr( $host, 0, $dot_pos );
				if( $next_dot_pos = strrpos( $host, '.' ) )
					$domain = substr( $host, $next_dot_pos + 1 ) . ".$domain";
			}
			$domain = ".$domain";

			setrawcookie( $this->opt_out_cookie_name, '1', $lifetime = time() + WEEK_IN_SECONDS, '/', 
				$domain, ( 'https' === parse_url( $site_url, PHP_URL_SCHEME ) ), true );
			$_COOKIE[$this->opt_out_cookie_name] = '1';
		}

		if( $this->has_user_opted_out() ) {
			$this->do_not_track_reason = 'User opted out.';
			return;
		}

		$this->request_ip = $_SERVER['REMOTE_ADDR'];
		if( $this->track_internal_ips )
			$this->request_ip = (string) filter_var( $this->request_ip, FILTER_VALIDATE_IP );
		else
			$this->request_ip = (string) filter_var( $this->request_ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		$this->request_ip_packed = @inet_pton( $this->request_ip );

		if( empty( $this->request_ip ) || empty( $this->request_ip_packed ) ) {
			$this->do_not_track_reason = 'Invalid or internal IP address.';
			return;
		}

		if( !empty( $this->do_not_track_ips ) ) {
			$do_not_track_ips_cache_key = $this->do_not_track_ips;
			if( is_array( $do_not_track_ips_cache_key ) ) // Support serialized arrays for PHP 5.6
				$do_not_track_ips_cache_key = serialize( $do_not_track_ips_cache_key );

			// Try to pull the whitelisted ips array from the cache to avoid building it on every request
			$do_not_track_ips = wp_cache_get( $do_not_track_ips_cache_key, 'wp_simple_google_analytics_do_not_track_ips' );
			if( false === $do_not_track_ips ) {
				// Build whitelisted ips array
				$do_not_track_ips = $this->do_not_track_ips;
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
			$this->do_not_track_ips = $do_not_track_ips;

			// Check if request ip should not be tracked
			$request_ip_packed_len = strlen( $this->request_ip_packed );
			$request_ip_binary = unpack( 'H*', $this->request_ip_packed ); // Subnet in Hex
			foreach( $request_ip_binary as $i => $h ) $request_ip_binary[$i] = base_convert($h, 16, 2); // Array of Binary
			$request_ip_binary = implode( '', $request_ip_binary ); // Subnet in Binary, only network bits
			$do_not_track = false;

			foreach( $this->do_not_track_ips as $do_not_track_ip ) {
				if( $request_ip_packed_len != $do_not_track_ip['ip_len'] ) // Don't compare IPv4 to IPv6 addresses and vice versa
					continue;

				if( $this->request_ip_packed == $do_not_track_ip['ip'] ) {
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
				return; // Do nothing ip this is not to be tracked
			}
		}

		if( !$this->track_bots ) {
			$user_agent = strtolower( (string) $_SERVER['HTTP_USER_AGENT'] );
			
			if( '' === $user_agent
				|| !empty( $_SERVER['HTTP_X_SCANNER'] ) // Netsparker scanner
				|| false !== strpos( $user_agent, '@' ) // Legitimate web crawlers add an email or url as contact information to user agent
				|| false !== strpos( $user_agent, 'http://' )
				|| false !== strpos( $user_agent, 'https://' )
				|| !preg_match( '#^[^/]+/[\d\.]+#', $user_agent ) // Valid user agent strings start with <product>/<product-version>
				|| preg_match( '/\b[\w\-]*(?:bot|crawler|archiver|transcoder|spider|uptime|validator|fetcher|java|python|facebookexternalhit|lighthouse)\b/', $user_agent ) ) {
				$request_host = (string) wp_cache_get( $this->request_ip, 'wp_simple_google_analytics_gethostbyaddr' );
				if( '' === $request_host ) {
					set_error_handler( array( $this, 'throwException' ) );
					try {
						// Pull all records at once to avoid multiple domain lookups
						$request_host = strtolower( (string) gethostbyaddr( $this->request_ip ) );
					} catch (Exception $e) {
						// DNS server was unreachable
					}
					restore_error_handler();
					wp_cache_set( $this->request_ip, $request_host, 'wp_simple_google_analytics_gethostbyaddr', DAY_IN_SECONDS );
				}

				if( '' !== $request_host 
					&& $this->request_ip !== $request_host 
					// Allow google traffic for site verification, pagespeed insights, etc.
					// Google Analytics filters google traffic out anyway.
					&& 'google.com' !== substr( $request_host, -10 ) 
					&& 'googlebot.com' !== substr( $request_host, -13 ) ) {
					$this->do_not_track_reason = "Bot traffic detected or missing User Agent.";
					return;
				}
			}
		}

		$this->analytics_js = $this->get_analytics_js();
	}

	public function add_shortcodes() {
		foreach( $this->shortcodes as $shortcode )
			add_shortcode( $shortcode, array( $this, 'shortcode_callback' ) );
	}

	public function shortcode_callback( $atts, $content, $shortcode_tag ) {
		$params = array();
		if( is_array( $atts ) )
			$params = $atts;
		$output = call_user_func( $shortcode_tag, $params );
		return $output;
	}

	public function add_referrer_policy_header( $headers ) {
		$headers['Referrer-Policy'] = 'default, same-origin, strict-origin-when-cross-origin';

		return $headers;
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

			<?php if( $user_id = get_current_user_id() ) : ?>
				googleAnalytics('set', 'userId', '<?php echo md5( $user_id ); ?>');
			<?php endif; ?>

			googleAnalytics('set', 'anonymizeIp', true);
			googleAnalytics('set', 'allowAdFeatures', false);
			googleAnalytics('set', 'forceSSL', true);
			googleAnalytics('set', 'transport', 'beacon');
			googleAnalytics('set', 'page', '<?php echo $this->sanitize_query_vars( $this->self_uri( true ) ); ?>');
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

	public function has_user_opted_out() {
		return !empty( $_COOKIE[$this->opt_out_cookie_name] );
	}

	/**
	 * Helper functions
	 */

	public function sanitize_query_vars( $url ) {
		global $wp;

		$question_mark_pos = strpos( $url, '?' );
		if( false === $question_mark_pos )
			return $url;

		$query_string = array();
		$allowed_query_vars = apply_filters( 'google_analytics_allowed_query_parameters', array_flip( $wp->public_query_vars ) );
		parse_str( substr( $url, $question_mark_pos + 1 ), $query_string );
		$query_string = array_intersect_key( $query_string, $allowed_query_vars );

		$url = substr( $url, 0, $question_mark_pos );
		if( !empty( $query_string ) )
			$url .= '?' . http_build_query( $query_string, null, ini_get('arg_separator.output'), PHP_QUERY_RFC3986 );
		return $url;
	}

	public function self_uri( $only_script_name ){
		$url = 'http';
		$script_name = '';
		if ( isset( $_SERVER['REQUEST_URI'] ) ):
			$script_name = $_SERVER['REQUEST_URI'];
		else:
			$script_name = $_SERVER['PHP_SELF'];
			if ( $_SERVER['QUERY_STRING'] > ' ' ):
				$script_name .= '?' . $_SERVER['QUERY_STRING'];
			endif;
		endif;

		if( $only_script_name )
			return $script_name;

		if ( ( isset( $_SERVER['HTTPS'] ) && $_SERVER['HTTPS'] == 'on' ) || $_SERVER['SERVER_PORT'] == '443' )
			$url .= 's';

		$url .= '://';
		if ( $_SERVER['SERVER_PORT'] != '80' && $_SERVER['SERVER_PORT'] != '443' ):
			$url .= $_SERVER['HTTP_HOST'] . ':' . $_SERVER['SERVER_PORT'] . $script_name;
		else:
			$url .= $_SERVER['HTTP_HOST'] . $script_name;
		endif;

		return $url;
	}

	public function throwException( $severity, $message, $file, $line ) {
		if ( !( error_reporting() & $severity ) )
			return; // This error code is not included in error_reporting
		throw new ErrorException( $message, 0, $severity, $file, $line );
	}
}

$WPSimpleGoogleAnalytics = WPSimpleGoogleAnalytics::object();
$WPSimpleGoogleAnalytics->init();