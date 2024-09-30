<?php
/*
Plugin Name: WP Simple Google Analytics 4
Plugin URI: https://github.com/msigley
Description: Simple Google Analytics 4 implementation that avoids using cookies and external javascript.
Version: 2.0.7
Author: Matthew Sigley
License: GPL2
*/

class WPSimpleGoogleAnalytics4 {
	private static $object = null;
	const cookie_name = 'wps_ga4';
	const cookie_lifetime = YEAR_IN_SECONDS * 2;
	const opt_out_cookie_name = 'wps_ga4_opt_out';
	const hash_algo = 'joaat';
	const hash_byte_length = 4;

	private $tag_id = null;
	private $debug = false;
	private $gtag_js_url = 'https://www.googletagmanager.com/gtag/js';
	private $gtag_js = null;
	private $gtag_js_file = '';
	private $request_ip = null;
	private $request_ip_packed = null;
	private $track_internal_ips = false;
	private $track_bots = false;
	private $do_not_track_ips = false;
	private $do_not_track_reason = false;
	private $shortcodes = array( 'google_analytics_4_opt_out_link' );
	private $utm_query_vars = array( 'utm_id' , 'utm_source', 'utm_medium', 'utm_campaign', 'utm_source_platform', 'utm_term', 'utm_content' );
	private $allowed_query_vars = array( 
		'gclid', // Google Click ID for Google Ads (AdWords)
		'dclid', // DoubleClick Click ID for Google Display Ads
		'_gl' 
	); // Google Ads and url passthrough
	private $client_id = false;

	private function __construct() {
		$wp_upload_dir_info = wp_upload_dir( null, false );
		$this->gtag_js_file = untrailingslashit( $wp_upload_dir_info['basedir'] ) . '/wpsga4/g.js';

		if( defined( 'GOOGLE_ANALYTICS_TAG_ID' ) )
			$this->tag_id = GOOGLE_ANALYTICS_TAG_ID;

		if( defined( 'GOOGLE_ANALYTICS_DEBUG' ) )
			$this->debug = !empty( GOOGLE_ANALYTICS_DEBUG );

		if( defined( 'GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS' ) )
			$this->track_internal_ips = !empty( GOOGLE_ANALYTICS_TRACK_INTERNAL_IPS );

		if( defined( 'GOOGLE_ANALYTICS_TRACK_BOTS' ) )
			$this->track_bots = !empty( GOOGLE_ANALYTICS_TRACK_BOTS );

		if( defined( 'GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS' ) )
			$this->do_not_track_ips = GOOGLE_ANALYTICS_DO_NOT_TRACK_IPS;
	}
	
	static function &object() {
		if ( ! self::$object instanceof WPSimpleGoogleAnalytics4 ) {
			self::$object = new WPSimpleGoogleAnalytics4();
		}
		return self::$object;
	}

	public function activation() {}

	public function deactivation() {
		wp_cache_flush();
	}

	public function init() {
		//Plugin activation/deactivation
		register_activation_hook( __FILE__, array($this, 'activation') );
		register_deactivation_hook( __FILE__, array($this, 'deactivation') );

		//General API
		require_once 'api.php';

		add_action( 'wp_print_footer_scripts', array( $this, 'print_analytics_js' ), 999 );

		add_action( 'init', array( $this, 'add_shortcodes' ) );

		add_filter( 'wp_headers', array( $this, 'add_referrer_policy_header' ) );

		if( empty( $this->tag_id ) ) {
			$this->do_not_track_reason = 'Missing tag id.';
			return;
		}

		if( is_admin() ) {
			$this->do_not_track_reason = 'In admin area or responding to an ajax request.';
			return;
		}

		if( isset( $_REQUEST['ga_opt_out'] ) )
			$this->set_cookie( self::opt_out_cookie_name, '1', YEAR_IN_SECONDS );

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
			$do_not_track_ips = wp_cache_get( $do_not_track_ips_cache_key, 'wp_simple_google_analytics_4_do_not_track_ips' );
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
				wp_cache_set( $do_not_track_ips_cache_key, $do_not_track_ips, 'wp_simple_google_analytics_4_do_not_track_ips', DAY_IN_SECONDS );
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
				$this->do_not_track_reason = "This IP address is set to not be tracked. ({$_SERVER['REMOTE_ADDR']})";
				return; // Do nothing ip this is not to be tracked
			}
		}

		if( !$this->track_bots ) {
			$user_agent = strtolower( (string) $_SERVER['HTTP_USER_AGENT'] );
			
			if( ( '' === $user_agent
				|| !empty( $_SERVER['HTTP_X_SCANNER'] ) // Netsparker scanner
				|| false !== strpos( $user_agent, '@' ) // Legitimate web crawlers add an email or url as contact information to user agent
				|| false !== strpos( $user_agent, 'http://' )
				|| false !== strpos( $user_agent, 'https://' )
				|| !preg_match( '#^[^/]+/[\d\.]+#', $user_agent ) // Valid user agent strings start with <product>/<product-version>
				|| preg_match( '/\b[\w\-]*(?:bot|crawler|archiver|transcoder|spider|uptime|validator|fetcher|java|python|facebookexternalhit|lighthouse)\b/', $user_agent ) )
				&& !preg_match( '/\bgooglebot|googleother|-google|google-\b/', $user_agent ) // Allow google traffic for site verification, pagespeed insights, etc.
				&& apply_filters( 'wp_simple_google_analytics_4_is_bot', true )
				) {
				$this->do_not_track_reason = "Bot traffic detected or missing User Agent.";
				return;
			}
		}

		// Initialize Client ID
		// Cookie needs to be set early here before headers are sent
		if( !empty( $_COOKIE[self::cookie_name] ) ) {
			list( $client_id, $cookie_timestamp ) = explode( '|', $_COOKIE[self::cookie_name], 2 );
			if( $this->validate_client_id( $client_id ) ) {
				$cookie_timestamp = (int) $cookie_timestamp;
				$this->set_client_id( $client_id, time() - $cookie_timestamp > WEEK_IN_SECONDS ); // Safari expires JS set cookies in a week
			}
		} else {
			$this->set_client_id( $this->generate_client_id(), true );
		}
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

	private function get_gtag_js_url() {
		return $this->gtag_js_url . '?id=' . $this->tag_id;
	}

	public function print_analytics_js() {
		if( current_user_can( 'edit_posts' ) )
			$this->do_not_track_reason = 'Current user can edit posts.';

		if( !empty( $this->do_not_track_reason ) ) {
			?>
			<!-- Google Analytics 4. Not tracking. <?php echo $this->do_not_track_reason; ?> -->
			<?php
			return;
		}

		// Disable tracking except for analytics by gtag.js
		$consent = new StdClass;
		$consent->ad_storage = 'denied';
		$consent->ad_user_data = 'denied';
		$consent->ad_personalization = 'denied';
		$consent->analytics_storage = 'granted';
		$consent->functionality_storage = 'denied';
		$consent->personalization_storage = 'denied';
		$consent->security_storage = 'denied';

		// Set is global settings
		$set = new StdClass;
		$set->client_id = $this->get_client_id();
		if( $this->debug )
			$set->debug_mode = true;

		// Data privacy settings
		$set->allow_google_signals = true; // Needed for Google Ads report
		$set->allow_ad_personalization_signals = false;
		$set->restricted_data_processing = true;
		$set->ads_data_redaction = true;
		$set->url_passthrough = true;

		// In Google Analytics 4, IP masking is not necessary since IP addresses are not logged or stored.
		// https://support.google.com/analytics/answer/9019185#IP
		// HTTPS is also default in GA4.
		// These settings were anonymizeIp and forceSSL in UA.

		// Cookie settings
		$site_url = parse_url( get_site_url() );
		if( empty( $site_url['path'] ) )
			$site_url['path'] = '/';
		
		$set->cookie_domain = $site_url['host'];
		$set->cookie_path = $site_url['path'];
		$set->cookie_flags = 'SameSite=None;Secure';
		$set->cookie_expires = self::cookie_lifetime; // Two years
		$set->cookie_update = false;

		// Google Ad conversion tracking
		$set->store_gac = false;
		$query_string = parse_url( $this->self_uri(), PHP_URL_QUERY );
		if( !empty( $query_string ) ) {
			parse_str( $query_string, $query_vars );
			foreach( $this->utm_query_vars as $utm_query_var ) {
				if( !isset( $query_vars[$utm_query_var] ) )
					continue;
				if( !isset( $set->campaign ) )
					$set->campaign = new StdClass;
				// Use substr() to remove the 'utm_' prefix in the set parameters.
				$set->campaign->{ substr( $utm_query_var, 4 ) } = $query_vars[$utm_query_var];
			}
		}

		// Sanitize page parameters for privacy
		$set->page_location = $this->sanitize_query_vars( $this->self_uri() );
		$set->page_referrer = $this->sanitize_query_vars( (string) filter_input( INPUT_SERVER, 'HTTP_REFERER', FILTER_VALIDATE_URL, FILTER_FLAG_SCHEME_REQUIRED|FILTER_FLAG_HOST_REQUIRED ) );

		// Config is GA only settings
		$config = new StdClass;
		$config->send_page_view = false;
		?>
		<!-- Google Analytics 4 --> 
		<script>
			window.dataLayer = window.dataLayer || [];
			function gtag(){ dataLayer.push(arguments); }

			gtag( 'consent', 'update', <?php echo json_encode( $consent ); ?> ); // Use update instead of default to avoid consent managers overriding this.
			
			var gtag_send = function(){
				gtag( 'js', new Date() );
				gtag( 'set', <?php echo json_encode( $set ); ?> );
				gtag( 'config', '<?php echo $this->tag_id; ?>', <?php echo json_encode( $config ); ?> );
				gtag( 'event', 'page_view' );
			}

			var load_gtag = function() {
				let script = document.createElement( 'script' );
				script.async = true;
				script.src = '<?php echo $this->get_gtag_js_url(); ?>';
				script.addEventListener( 'load', gtag_send );
				document.body.append( script );
			};

			if( 'loading' === document.readyState )
				window.addEventListener( 'DOMContentLoaded', load_gtag );
			else
				load_gtag();
		</script>
		<!-- End Google Analytics 4 -->
		<?php
	}

	public function has_user_opted_out() {
		return !empty( $_COOKIE[self::opt_out_cookie_name] );
	}

	public function get_client_id() {
		return $this->client_id;
	}

	public function set_client_id( $client_id, $set_cookie ) {
		$this->client_id = $client_id;
		if( $set_cookie )
			$this->set_cookie( self::cookie_name, $client_id . '|' . time() );
	}

	public function generate_client_id() {
		return $this->hash( $this->request_ip ) . 
			'.' . $this->hash( $_SERVER['HTTP_USER_AGENT'] ) . 
			'.' . $this->hash( microtime( true ) ) . 
			'.' . bin2hex( $this->entropy( self::hash_byte_length ) ); 
	}

	public function validate_client_id( $client_id ) {
		$hash_regex = '[0-9a-f]{' . self::hash_byte_length * 2 . '}';
		return preg_match( "/^$hash_regex\.$hash_regex\.$hash_regex\.$hash_regex$/", $client_id );
	}

	/**
	 * Helper functions
	 */

	public function sanitize_query_vars( $url ) {
		global $wp;

		$url = (string) $url;

		$question_mark_pos = strpos( $url, '?' );
		if( false === $question_mark_pos )
			return $url;

		$query_string = array();
		$allowed_query_vars = apply_filters( 'google_analytics_allowed_query_parameters', array_flip( $wp->public_query_vars ) + array_flip( $this->allowed_query_vars ) );
		parse_str( substr( $url, $question_mark_pos + 1 ), $query_string );
		$query_string = array_intersect_key( $query_string, $allowed_query_vars );

		$url = substr( $url, 0, $question_mark_pos );
		if( !empty( $query_string ) )
			$url .= '?' . http_build_query( $query_string, null, ini_get('arg_separator.output'), PHP_QUERY_RFC3986 );
		return $url;
	}

	public function self_uri( $only_script_name = false ){
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

	private function hash( $string ) {
		return substr( hash( self::hash_algo, $string ), 0, self::hash_byte_length * 2 );
	}

	/**
	 * Generate random bytes using the best available CSPRNG
	 *
	 * @author Jonathan Davis (Shopp), Matthew Sigley
	 *
	 * @return string String of random bytes or false on failure
	 **/
	private function entropy( $num_bytes ) {
		$entropy = false;

		//PHP 7
		if( is_callable( 'random_bytes' ) )
			return random_bytes( $num_bytes );

		//PHP 5.5.28+, and 5.6.12+ with OpenSSL extension
		if( is_callable( 'openssl_random_pseudo_bytes' ) ) {
			$entropy = openssl_random_pseudo_bytes( $num_bytes, $strong );
			// Don't use openssl if a strong crypto algo wasn't used
			if ( !empty($entropy) && $strong === true )
				return $entropy;
		}
		
		//UNIX
		if( DIRECTORY_SEPARATOR === '/' ) {
			if( !empty( ini_get( 'open_basedir' ) ) && @is_readable( '/dev/urandom' ) && $h = fopen( '/dev/urandom', 'rb' ) ) {
			if( function_exists( 'stream_set_read_buffer' ) )
				stream_set_read_buffer( $h, 0 );
				$entropy = @fread( $h, $num_bytes );
				fclose( $h );
				if ( !empty($entropy) )
					return $entropy;
			}
		}

		//Windows with extension enabled
		if( class_exists( 'COM' ) ) {
			try {
				$CAPICOM = new COM( 'CAPICOM.Utilities.1' );
				$entropy = base64_decode( $CAPICOM->GetRandom( $num_bytes, 0 ) );
				if ( !empty($entropy) )
					return $entropy;
			} catch ( Exception $E ) {}
		}
		
		//mcrypt if nothing else is available
		if( is_callable( 'mcrypt_create_iv' ) ) {
			$entropy = mcrypt_create_iv( $num_bytes, MCRYPT_DEV_URANDOM );
			if ( !empty($entropy) )
				return $entropy;
		}

		//No CSPRNG available
		trigger_error( "No cryptographically secure pseudorandom number generator is available in the current PHP environment." );
		return false;
	}

	private function set_cookie( $cookie_name, $cookie_value, $cookie_lifetime = self::cookie_lifetime ) {
		$site_url = parse_url( get_site_url() );
		if( empty( $site_url['path'] ) )
			$site_url['path'] = '/';
		
		setrawcookie( $cookie_name, $cookie_value, time() + self::cookie_lifetime, $site_url['path'], $site_url['host'], true, true );
		$_COOKIE[$cookie_name] = $cookie_value;
	}

	public function throwException( $severity, $message, $file, $line ) {
		if ( !( error_reporting() & $severity ) )
			return; // This error code is not included in error_reporting
		throw new ErrorException( $message, 0, $severity, $file, $line );
	}
}

$WPSimpleGoogleAnalytics4 = WPSimpleGoogleAnalytics4::object();
$WPSimpleGoogleAnalytics4->init();