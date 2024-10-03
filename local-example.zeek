##! Zeek local site policy. Customize as appropriate.
##!
##! See https://github.com/zeek/zeekctl
##!     https://docs.zeek.org/en/stable/script-reference/scripts.html
##!     https://github.com/zeek/zeek/blob/master/scripts/site/local.zeek

global true_regex: pattern = /^\s*(?i:t(rue)?|y(es)?|on|1)\s*$/;

global disable_stats = (getenv("ZEEK_DISABLE_STATS") == true_regex) ? T : F;
global disable_hash_all_files = (getenv("ZEEK_DISABLE_HASH_ALL_FILES") == true_regex) ? T : F;
global disable_log_passwords = (getenv("ZEEK_DISABLE_LOG_PASSWORDS") == true_regex) ? T : F;
global disable_ssl_validate_certs = (getenv("ZEEK_DISABLE_SSL_VALIDATE_CERTS") == true_regex) ? T : F;
global disable_track_all_assets = (getenv("ZEEK_DISABLE_TRACK_ALL_ASSETS") == true_regex) ? T : F;
global zeek_local_nets_str = getenv("ZEEK_LOCAL_NETS");

redef Broker::default_listen_address = "127.0.0.1";
redef ignore_checksums = T;

global capture_filter_str = getenv("CAPTURE_FILTER");
@if (capture_filter_str != "")
  redef restrict_filters += { ["user-defined capture filter"] = capture_filter_str };
@endif

global json_format = (getenv("ZEEK_JSON") == true_regex) ? T : F;
@if (json_format)
  redef LogAscii::use_json = T;
@endif

@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load frameworks/software/windows-version-detection
@load-sigs frameworks/signatures/detect-windows-shells
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/dhcp/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/ftp/detect-bruteforcing.zeek
@load protocols/ftp/software
@load protocols/http/detect-sqli
@load protocols/http/detect-webapps
@load protocols/http/header-names
@load protocols/http/software
@load protocols/http/software-browser-plugins
@load protocols/mysql/software
@load protocols/ssl/weak-keys
@load protocols/smb/log-cmds
@load protocols/smtp/software
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/geo-data
@load protocols/ssh/interesting-hostnames
@load protocols/ssh/software
@load protocols/ssl/known-certs
@load protocols/ssl/log-hostcerts-only
@if (!disable_ssl_validate_certs)
  @load protocols/ssl/validate-certs
@endif
@if (!disable_track_all_assets)
  @load tuning/track-all-assets.zeek
@endif
@if (!disable_hash_all_files)
  @load frameworks/files/hash-all-files
@endif
@if (!disable_stats)
  @load policy/misc/stats
  @load policy/misc/capture-loss
@endif
@load policy/protocols/conn/vlan-logging
@load policy/protocols/conn/mac-logging
@load policy/protocols/modbus/known-masters-slaves
@load policy/frameworks/notice/community-id

# @load frameworks/files/detect-MHR
# @load policy/misc/loaded-scripts

@load packages
@load custom

event zeek_init() &priority=-5 {

  if (zeek_local_nets_str != "") {
    local nets_strs = split_string(zeek_local_nets_str, /,/);
    if (|nets_strs| > 0) {
      for (net_idx in nets_strs) {
        local local_subnet = to_subnet(nets_strs[net_idx]);
        if (local_subnet != [::]/0) {
          add Site::local_nets[local_subnet];
        }
      }
    }
  }

}

@if (!disable_log_passwords)
  redef HTTP::default_capture_password = T;
  redef FTP::default_capture_password = T;
  redef SOCKS::default_capture_password = T;
@endif
redef HTTP::log_client_header_names = T;
redef HTTP::log_server_header_names = T;