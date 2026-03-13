/*jslint browser:true */

var jQuery;
var wssh = {};


(function() {
  // For FormData without getter and setter
  var proto = FormData.prototype,
      data = {};

  if (!proto.get) {
    proto.get = function (name) {
      if (data[name] === undefined) {
        var input = document.querySelector('input[name="' + name + '"]'),
            value;
        if (input) {
          if (input.type === 'file') {
            value = input.files[0];
          } else {
            value = input.value;
          }
          data[name] = value;
        }
      }
      return data[name];
    };
  }

  if (!proto.set) {
    proto.set = function (name, value) {
      data[name] = value;
    };
  }
}());


jQuery(function($){
  var status = $('#status'),
      button = $('.btn-primary'),
      form_container = $('.form-container'),
      waiter = $('#waiter'),
      term_type = $('#term'),
      style = {},
      default_title = 'WebSSH',
      title_element = document.querySelector('title'),
      form_id = '#connect',
      debug = document.querySelector(form_id).noValidate,
      custom_font = document.fonts ? document.fonts.values().next().value : undefined,
      default_fonts,
      DISCONNECTED = 0,
      CONNECTING = 1,
      CONNECTED = 2,
      messages = {1: 'This client is connecting ...', 2: 'This client is already connnected.'},
      key_max_size = 16384,
      fields = ['hostname', 'port', 'username'],
      form_keys = fields.concat(['password', 'totp']),
      url_safe_keys = fields,
      opts_keys = ['bgcolor', 'title', 'encoding', 'command', 'term', 'fontsize', 'fontcolor', 'cursor'],
      url_form_data = {},
      url_opts_data = {},
      validated_form_data,
      event_origin,
      hostname_tester = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))|(^\s*((?=.{1,255}$)(?=.*[A-Za-z].*)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*)\s*$)/;


  // ===================== Tab Manager =====================

  var tabManager = {
    tabs: {},
    activeTabId: null,
    tabCounter: 0,

    createTab: function() {
      var tabId = ++this.tabCounter;
      var container = document.createElement('div');
      container.className = 'terminal-pane';
      container.id = 'terminal-pane-' + tabId;
      document.getElementById('terminals-container').appendChild(container);

      // Create tab item element
      var tabItem = document.createElement('div');
      tabItem.className = 'tab-item';
      tabItem.setAttribute('data-tab-id', tabId);

      var statusDot = document.createElement('span');
      statusDot.className = 'tab-status';

      var label = document.createElement('span');
      label.className = 'tab-label';
      label.textContent = 'New Connection';

      var closeBtn = document.createElement('button');
      closeBtn.className = 'tab-close';
      closeBtn.innerHTML = '&times;';
      closeBtn.title = 'Close tab';

      tabItem.appendChild(statusDot);
      tabItem.appendChild(label);
      tabItem.appendChild(closeBtn);
      document.getElementById('tab-list').appendChild(tabItem);

      // Tab click to activate
      var self = this;
      tabItem.addEventListener('click', function(e) {
        if (!e.target.classList.contains('tab-close')) {
          self.activateTab(tabId);
        }
      });

      // Close button
      closeBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        self.closeTab(tabId);
      });

      var tab = {
        id: tabId,
        label: 'New Connection',
        state: DISCONNECTED,
        term: null,
        fitAddon: null,
        sock: null,
        encoding: 'utf-8',
        decoder: null,
        containerEl: container,
        tabItemEl: tabItem,
        title: ''
      };

      this.tabs[tabId] = tab;

      // Show tab bar
      $('#tab-bar').addClass('visible');
      $('body').addClass('has-tabs');

      this.activateTab(tabId);
      return tab;
    },

    activateTab: function(tabId) {
      var tab = this.tabs[tabId];
      if (!tab) return;

      // Deactivate current
      if (this.activeTabId !== null && this.tabs[this.activeTabId]) {
        var oldTab = this.tabs[this.activeTabId];
        $(oldTab.containerEl).removeClass('active');
        $(oldTab.tabItemEl).removeClass('active');
      }

      this.activeTabId = tabId;
      $(tab.containerEl).addClass('active');
      $(tab.tabItemEl).addClass('active');

      // Dismiss any lingering status from other tabs
      dismiss_status();

      if (tab.state === CONNECTED && tab.term) {
        form_container.hide();
        // Fit after a brief delay so layout settles, then focus
        setTimeout(function() {
          if (tab.fitAddon) {
            tab.fitAddon.fit();
          }
          if (tab.term) {
            setTimeout(function() { tab.term.focus(); }, 50);
          }
        }, 10);
      } else {
        form_container.show();
      }

      // Update page title
      if (tab.state === CONNECTED && tab.title) {
        title_element.text = tab.title;
      } else {
        title_element.text = default_title;
      }

      // Rebind wssh proxy methods to this tab
      this.bindWssh(tab);
    },

    closeTab: function(tabId) {
      var tab = this.tabs[tabId];
      if (!tab) return;

      // Close WebSocket if connected
      if (tab.sock) {
        tab.sock.onclose = function() {}; // prevent re-entrant handling
        tab.sock.close();
        tab.sock = null;
      }

      // Dispose terminal
      if (tab.term) {
        tab.term.dispose();
        tab.term = null;
      }

      // Remove DOM elements
      tab.containerEl.parentNode.removeChild(tab.containerEl);
      tab.tabItemEl.parentNode.removeChild(tab.tabItemEl);

      delete this.tabs[tabId];

      // If was active, activate nearest remaining tab
      if (this.activeTabId === tabId) {
        this.activeTabId = null;
        var ids = this.getTabIds();
        if (ids.length > 0) {
          // Find nearest tab
          var idx = 0;
          for (var i = 0; i < ids.length; i++) {
            if (ids[i] > tabId) break;
            idx = i;
          }
          this.activateTab(ids[idx]);
        } else {
          // No tabs left, create new one
          this.createTab();
        }
      }
    },

    getActiveTab: function() {
      return this.tabs[this.activeTabId] || null;
    },

    updateTabLabel: function(tabId, label) {
      var tab = this.tabs[tabId];
      if (!tab) return;
      tab.label = label;
      tab.title = label;
      $(tab.tabItemEl).find('.tab-label').text(label);
    },

    updateTabStatus: function(tabId) {
      var tab = this.tabs[tabId];
      if (!tab) return;
      var dot = $(tab.tabItemEl).find('.tab-status');
      dot.removeClass('connected connecting');
      if (tab.state === CONNECTED) {
        dot.addClass('connected');
      } else if (tab.state === CONNECTING) {
        dot.addClass('connecting');
      }
    },

    getTabIds: function() {
      var ids = [];
      for (var k in this.tabs) {
        if (this.tabs.hasOwnProperty(k)) {
          ids.push(parseInt(k, 10));
        }
      }
      ids.sort(function(a, b) { return a - b; });
      return ids;
    },

    getTabByIndex: function(index) {
      var ids = this.getTabIds();
      if (index >= 0 && index < ids.length) {
        return ids[index];
      }
      return null;
    },

    bindWssh: function(tab) {
      // Reset wssh except connect
      var name;
      for (name in wssh) {
        if (wssh.hasOwnProperty(name) && name !== 'connect') {
          delete wssh[name];
        }
      }

      if (!tab || tab.state !== CONNECTED || !tab.term || !tab.sock) return;

      wssh.set_encoding = tab._set_encoding || undefined;
      wssh.reset_encoding = tab._reset_encoding || undefined;

      wssh.geometry = function() {
        var geometry = current_geometry(tab.term);
        console.log('Current window geometry: ' + JSON.stringify(geometry));
      };

      wssh.send = function(data) {
        if (!tab.sock) {
          console.log('Websocket was already closed');
          return;
        }
        if (typeof data !== 'string') {
          console.log('Only string is allowed');
          return;
        }
        try {
          JSON.parse(data);
          tab.sock.send(data);
        } catch (SyntaxError) {
          data = data.trim() + '\r';
          tab.sock.send(JSON.stringify({'data': data}));
        }
      };

      wssh.resize = function(cols, rows) {
        if (!tab.term) {
          console.log('Terminal was already destroyed');
          return;
        }
        var valid_args = false;
        if (cols > 0 && rows > 0) {
          var geometry = current_geometry(tab.term);
          if (cols <= geometry.cols && rows <= geometry.rows) {
            valid_args = true;
          }
        }
        if (!valid_args) {
          console.log('Unable to resize terminal to geometry: ' + format_geometry(cols, rows));
        } else {
          tab.term.on_resize(cols, rows);
        }
      };

      wssh.set_bgcolor = function(color) {
        set_backgound_color(tab.term, color);
      };

      wssh.set_fontcolor = function(color) {
        set_font_color(tab.term, color);
      };

      wssh.custom_font = function() {
        update_font_family(tab.term);
      };

      wssh.default_font = function() {
        reset_font_family(tab.term);
      };
    }
  };


  // ===================== Utility Functions =====================

  function store_items(names, data) {
    var i, name, value;

    for (i = 0; i < names.length; i++) {
      name = names[i];
      value = data.get(name);
      if (value){
        window.localStorage.setItem(name, value);
      }
    }
  }


  function get_host_key(data) {
    var hostname = data.get ? data.get('hostname') : data.hostname;
    var port = data.get ? data.get('port') : data.port;
    if (!hostname) return null;
    return 'command:' + hostname + ':' + (port || '22');
  }


  function store_default_command(data) {
    var key = get_host_key(data);
    if (!key) return;
    var command = $('#default-command').val().trim();
    if (command) {
      window.localStorage.setItem(key, command);
    } else {
      window.localStorage.removeItem(key);
    }
  }


  function restore_default_command(hostname, port) {
    if (!hostname) return;
    var key = get_host_key({hostname: hostname, port: port});
    if (!key) return;
    var command = window.localStorage.getItem(key);
    $('#default-command').val(command || '');
  }


  function restore_items(names) {
    var i, name, value;

    for (i=0; i < names.length; i++) {
      name = names[i];
      value = window.localStorage.getItem(name);
      if (value) {
        var el = $('#'+name);
        el.val(value);
        if (name === 'hostname' && el.is('select')) {
          el.trigger('change');
        }
      }
    }
  }


  function populate_form(data) {
    var names = form_keys.concat(['passphrase']),
        i, name;

    for (i=0; i < names.length; i++) {
      name = names[i];
      $('#'+name).val(data.get(name));
    }
  }


  function get_object_length(object) {
    return Object.keys(object).length;
  }


  function decode_uri_component(uri) {
    try {
      return decodeURIComponent(uri);
    } catch(e) {
      console.error(e);
    }
    return '';
  }


  function parse_url_data(string, allowed_keys, opts_keys, form_map, opts_map) {
    var i, pair, key, val,
        arr = string.split('&');

    for (i = 0; i < arr.length; i++) {
      pair = arr[i].split('=');
      key = pair[0].trim().toLowerCase();
      val = pair.slice(1).join('=').trim();

      if (allowed_keys.indexOf(key) >= 0) {
        form_map[key] = val;
      } else if (opts_keys.indexOf(key) >=0) {
        opts_map[key] = val;
      }
    }
  }


  function parse_xterm_style() {
    var text = $('.xterm-helpers style').text();
    var arr = text.split('xterm-normal-char{width:');
    style.width = parseFloat(arr[1]);
    arr = text.split('div{height:');
    style.height = parseFloat(arr[1]);
  }


  function get_cell_size(term) {
    style.width = term._core._renderService._renderer.dimensions.actualCellWidth;
    style.height = term._core._renderService._renderer.dimensions.actualCellHeight;
  }


  function enter_fullscreen(term, containerEl) {
    $(containerEl).find('.terminal').addClass('fullscreen');
    term.fitAddon.fit();
  }


  function current_geometry(term) {
    return {'cols': term.cols, 'rows': term.rows};
  }


  function resize_terminal(term) {
    if (term.fitAddon) {
      term.fitAddon.fit();
    }
    var geometry = current_geometry(term);
    // Send the current size to the server (fit already resized the local terminal)
    term.send_resize(geometry.cols, geometry.rows);
  }


  function set_backgound_color(term, color) {
    term.setOption('theme', {
      background: color
    });
  }

  function set_font_color(term, color) {
    term.setOption('theme', {
      foreground: color
    });
  }

  function custom_font_is_loaded() {
    if (!custom_font) {
      console.log('No custom font specified.');
    } else {
      console.log('Status of custom font ' + custom_font.family + ': ' + custom_font.status);
      if (custom_font.status === 'loaded') {
        return true;
      }
      if (custom_font.status === 'unloaded') {
        return false;
      }
    }
  }

  function update_font_family(term) {
    if (term.font_family_updated) {
      console.log('Already using custom font family');
      return;
    }

    if (!default_fonts) {
      default_fonts = term.getOption('fontFamily');
    }

    if (custom_font_is_loaded()) {
      var new_fonts =  custom_font.family + ', ' + default_fonts;
      term.setOption('fontFamily', new_fonts);
      term.font_family_updated = true;
      console.log('Using custom font family ' + new_fonts);
    }
  }


  function reset_font_family(term) {
    if (!term.font_family_updated) {
      console.log('Already using default font family');
      return;
    }

    if (default_fonts) {
      term.setOption('fontFamily',  default_fonts);
      term.font_family_updated = false;
      console.log('Using default font family ' + default_fonts);
    }
  }


  function format_geometry(cols, rows) {
    return JSON.stringify({'cols': cols, 'rows': rows});
  }


  function read_as_text_with_decoder(file, callback, decoder) {
    var reader = new window.FileReader();

    if (decoder === undefined) {
      decoder = new window.TextDecoder('utf-8', {'fatal': true});
    }

    reader.onload = function() {
      var text;
      try {
        text = decoder.decode(reader.result);
      } catch (TypeError) {
        console.log('Decoding error happened.');
      } finally {
        if (callback) {
          callback(text);
        }
      }
    };

    reader.onerror = function (e) {
      console.error(e);
    };

    reader.readAsArrayBuffer(file);
  }


  function read_as_text_with_encoding(file, callback, encoding) {
    var reader = new window.FileReader();

    if (encoding === undefined) {
      encoding = 'utf-8';
    }

    reader.onload = function() {
      if (callback) {
        callback(reader.result);
      }
    };

    reader.onerror = function (e) {
      console.error(e);
    };

    reader.readAsText(file, encoding);
  }


  function read_file_as_text(file, callback, decoder) {
    if (!window.TextDecoder) {
      read_as_text_with_encoding(file, callback, decoder);
    } else {
      read_as_text_with_decoder(file, callback, decoder);
    }
  }


  function dismiss_status() {
    status.removeClass('visible');
  }

  status.on('click', dismiss_status);

  function log_status(text, to_populate) {
    console.log(text);
    if (text) {
      status.empty()
        .append($('<span>').text(text))
        .append('<button class="dismiss" title="Dismiss">&times;</button>');
      status.addClass('visible');
    } else {
      status.empty().removeClass('visible');
    }

    if (to_populate && validated_form_data) {
      populate_form(validated_form_data);
      validated_form_data = undefined;
    }

    if (waiter.css('display') !== 'none') {
      waiter.hide();
    }

    // Only show form if the active tab is disconnected
    var activeTab = tabManager.getActiveTab();
    if (activeTab && activeTab.state !== CONNECTED) {
      if (form_container.css('display') === 'none') {
        form_container.show();
      }
    }
  }


  // ===================== Per-Tab Ajax Callback =====================

  function make_ajax_callback(tab) {
    return function(resp) {
      button.prop('disabled', false);

      if (resp.status !== 200) {
        log_status(resp.status + ': ' + resp.statusText, true);
        tab.state = DISCONNECTED;
        tabManager.updateTabStatus(tab.id);
        return;
      }

      var msg = resp.responseJSON;
      if (!msg.id) {
        log_status(msg.status, true);
        tab.state = DISCONNECTED;
        tabManager.updateTabStatus(tab.id);
        return;
      }

      var ws_url = window.location.href.split(/\?|#/, 1)[0].replace('http', 'ws'),
          join = (ws_url[ws_url.length-1] === '/' ? '' : '/'),
          url = ws_url + join + 'ws?id=' + msg.id,
          sock = new window.WebSocket(url),
          encoding = 'utf-8',
          decoder = window.TextDecoder ? new window.TextDecoder(encoding) : encoding,
          termOptions = {
            cursorBlink: true,
            theme: {
              background: url_opts_data.bgcolor || 'black',
              foreground: url_opts_data.fontcolor || 'white',
              cursor: url_opts_data.cursor || url_opts_data.fontcolor || 'white'
            }
          };

      if (url_opts_data.fontsize) {
        var fontsize = window.parseInt(url_opts_data.fontsize);
        if (fontsize && fontsize > 0) {
          termOptions.fontSize = fontsize;
        }
      }

      var term = new window.Terminal(termOptions);
      var fitAddon = new window.FitAddon.FitAddon();
      term.fitAddon = fitAddon;
      term.loadAddon(fitAddon);

      // Store on tab
      tab.term = term;
      tab.fitAddon = fitAddon;
      tab.sock = sock;
      tab.encoding = encoding;
      tab.decoder = decoder;

      console.log(url);
      if (!msg.encoding) {
        console.log('Unable to detect the default encoding of your server');
        msg.encoding = encoding;
      } else {
        console.log('The deault encoding of your server is ' + msg.encoding);
      }

      function term_write(text) {
        if (tab.term) {
          tab.term.write(text);
          if (!tab.term.resized) {
            resize_terminal(tab.term);
            tab.term.resized = true;
          }
        }
      }

      function set_encoding(new_encoding) {
        if (!new_encoding) {
          console.log('An encoding is required');
          return;
        }

        if (!window.TextDecoder) {
          tab.decoder = new_encoding;
          tab.encoding = tab.decoder;
          console.log('Set encoding to ' + tab.encoding);
        } else {
          try {
            tab.decoder = new window.TextDecoder(new_encoding);
            tab.encoding = tab.decoder.encoding;
            console.log('Set encoding to ' + tab.encoding);
          } catch (RangeError) {
            console.log('Unknown encoding ' + new_encoding);
            return false;
          }
        }
      }

      // Store encoding functions on tab for wssh binding
      tab._set_encoding = set_encoding;
      tab._reset_encoding = function() {
        if (tab.encoding === msg.encoding) {
          console.log('Already reset to ' + msg.encoding);
        } else {
          set_encoding(msg.encoding);
        }
      };

      if (url_opts_data.encoding) {
        if (set_encoding(url_opts_data.encoding) === false) {
          set_encoding(msg.encoding);
        }
      } else {
        set_encoding(msg.encoding);
      }

      term.send_resize = function(cols, rows) {
        console.log('Sending resize to server: ' + format_geometry(cols, rows));
        if (tab.sock) {
          tab.sock.send(JSON.stringify({'resize': [cols, rows]}));
        }
      };

      term.on_resize = function(cols, rows) {
        if (cols !== this.cols || rows !== this.rows) {
          console.log('Resizing terminal to geometry: ' + format_geometry(cols, rows));
          this.resize(cols, rows);
        }
        this.send_resize(cols, rows);
      };

      term.onData(function(data) {
        if (tab.sock) {
          tab.sock.send(JSON.stringify({'data': data}));
        }
      });

      // Allow Alt-key shortcuts to pass through to document handler
      term.attachCustomKeyEventHandler(function(e) {
        if (e.altKey && (e.key === 't' || e.key === 'T' ||
            e.key === 'w' || e.key === 'W' ||
            e.key === 'ArrowLeft' || e.key === 'ArrowRight' ||
            (e.key >= '1' && e.key <= '9'))) {
          return false; // let the event propagate to the document handler
        }
        return true;
      });

      sock.onopen = function() {
        term.open(tab.containerEl);
        tab.state = CONNECTED;
        tabManager.updateTabLabel(tab.id, tab.title || default_title);
        tabManager.updateTabStatus(tab.id);

        // Clear sensitive fields after successful connection
        $('#password').val('');
        $('#totp').val('');

        // If this is the active tab, hide form and focus
        if (tabManager.activeTabId === tab.id) {
          form_container.hide();
          title_element.text = url_opts_data.title || tab.title || default_title;
          tabManager.bindWssh(tab);
        }

        // Fit terminal after layout has settled (form hidden)
        update_font_family(term);
        $(tab.containerEl).find('.terminal').addClass('fullscreen');
        requestAnimationFrame(function() {
          if (term.fitAddon) {
            term.fitAddon.fit();
            resize_terminal(term);
          }
          if (tabManager.activeTabId === tab.id) {
            setTimeout(function() { term.focus(); }, 50);
          }
        });

        var command = (url_opts_data.command || $('#default-command').val() || '').trim();
        if (command) {
          setTimeout(function () {
            if (tab.sock) {
              tab.sock.send(JSON.stringify({'data': command+'\r'}));
            }
          }, 500);
        }

        // Send keepalive every 30s to prevent proxy timeouts
        tab.keepaliveInterval = setInterval(function() {
          if (tab.sock && tab.sock.readyState === WebSocket.OPEN) {
            tab.sock.send(JSON.stringify({'keepalive': 1}));
          }
        }, 30000);
      };

      sock.onmessage = function(msg) {
        read_file_as_text(msg.data, term_write, tab.decoder);
      };

      sock.onerror = function(e) {
        console.error(e);
      };

      sock.onclose = function(e) {
        if (tab.keepaliveInterval) {
          clearInterval(tab.keepaliveInterval);
          tab.keepaliveInterval = null;
        }
        if (tab.term) {
          tab.term.dispose();
          tab.term = null;
        }
        tab.fitAddon = null;
        tab.sock = null;
        tab.state = DISCONNECTED;
        tabManager.updateTabStatus(tab.id);

        // Auto-close the tab unless it's the last one
        if (tabManager.getTabIds().length > 1) {
          tabManager.closeTab(tab.id);
          return;
        }

        // Only show form and status if this is the active tab
        if (tabManager.activeTabId === tab.id) {
          tabManager.bindWssh(tab);
          log_status(e.reason, true);
          title_element.text = default_title;
        }
      };
    };
  }


  // ===================== Connection Functions =====================

  function wrap_object(opts) {
    var obj = {};

    obj.get = function(attr) {
      return opts[attr] || '';
    };

    obj.set = function(attr, val) {
      opts[attr] = val;
    };

    return obj;
  }


  function clean_data(data) {
    var i, attr, val;
    var attrs = form_keys.concat(['privatekey', 'passphrase']);

    for (i = 0; i < attrs.length; i++) {
      attr = attrs[i];
      val = data.get(attr);
      if (typeof val === 'string') {
        data.set(attr, val.trim());
      }
    }
  }


  function validate_form_data(data) {
    clean_data(data);

    var hostname = data.get('hostname'),
        port = data.get('port'),
        username = data.get('username'),
        pk = data.get('privatekey'),
        key_source = data.get('key_source'),
        result = {
          valid: false,
          data: data,
          title: ''
        },
        errors = [], size;

    // Parse hostname:port shortcut (e.g. "foobar:2222")
    if (hostname && !allowed_hosts_configured && hostname.indexOf(':') > 0) {
      var parts = hostname.split(':');
      var parsed_port = parseInt(parts[parts.length - 1], 10);
      if (parsed_port > 0 && parsed_port <= 65535) {
        hostname = parts.slice(0, -1).join(':');
        if (!port) {
          port = parsed_port;
        }
        data.set('hostname', hostname);
        data.set('port', port);
      }
    }

    if (!hostname) {
      errors.push('Value of hostname is required.');
    } else if (!allowed_hosts_configured) {
      if (!hostname_tester.test(hostname)) {
         errors.push('Invalid hostname: ' + hostname);
      }
    }

    if (!port) {
      port = 22;
    } else {
      port = parseInt(port, 10);
      if (!(port > 0 && port <= 65535)) {
        errors.push('Invalid port: ' + port);
      }
    }

    if (!username) {
      errors.push('Value of username is required.');
    }

    if (key_source !== 'stored' && pk) {
      size = pk.size || pk.length;
      if (size > key_max_size) {
        errors.push('Invalid private key: ' + (pk.name || ''));
      }
    }

    if (!errors.length || debug) {
      result.valid = true;
      result.title = username + '@' + hostname + ':'  + port;
    }
    result.errors = errors;

    return result;
  }

  // Fix empty input file ajax submission error for safari 11.x
  function disable_file_inputs(inputs) {
    var i, input;

    for (i = 0; i < inputs.length; i++) {
      input = inputs[i];
      if (input.files.length === 0) {
        input.setAttribute('disabled', '');
      }
    }
  }


  function enable_file_inputs(inputs) {
    var i;

    for (i = 0; i < inputs.length; i++) {
      inputs[i].removeAttribute('disabled');
    }
  }


  function connect_without_options() {
    // use data from the form
    var tab = tabManager.getActiveTab();
    if (!tab || tab.state !== DISCONNECTED) {
      return;
    }

    var form = document.querySelector(form_id),
        inputs = form.querySelectorAll('input[type="file"]'),
        url = form.action,
        data, pk;

    disable_file_inputs(inputs);
    data = new FormData(form);
    pk = data.get('privatekey');
    enable_file_inputs(inputs);

    function ajax_post() {
      status.empty().removeClass('visible');
      button.prop('disabled', true);

      $.ajax({
          url: url,
          type: 'post',
          data: data,
          complete: make_ajax_callback(tab),
          cache: false,
          contentType: false,
          processData: false
      });
    }

    var result = validate_form_data(data);
    if (!result.valid) {
      log_status(result.errors.join('\n'));
      return;
    }

    var key_source = data.get('key_source');
    if (key_source === 'stored') {
      ajax_post();
    } else if (pk && pk.size && !debug) {
      read_file_as_text(pk, function(text) {
        if (text === undefined) {
            log_status('Invalid private key: ' + pk.name);
        } else {
          ajax_post();
        }
      });
    } else {
      ajax_post();
    }

    return result;
  }


  function connect_with_options(data) {
    // use data from the arguments
    var form = document.querySelector(form_id),
        url = data.url || form.action,
        _xsrf = form.querySelector('input[name="_xsrf"]');

    var result = validate_form_data(wrap_object(data));
    if (!result.valid) {
      log_status(result.errors.join('\n'));
      return;
    }

    var tab = tabManager.getActiveTab();

    data.term = term_type.val();
    data._xsrf = _xsrf.value;
    if (event_origin) {
      data._origin = event_origin;
    }

    status.text('').removeClass('visible');
    button.prop('disabled', true);

    $.ajax({
        url: url,
        type: 'post',
        data: data,
        complete: make_ajax_callback(tab)
    });

    return result;
  }


  function connect(hostname, port, username, password, privatekey, passphrase, totp) {
    // for console use
    var result, opts;
    var tab = tabManager.getActiveTab();

    if (!tab || tab.state !== DISCONNECTED) {
      if (tab) {
        console.log(messages[tab.state]);
      }
      return;
    }

    if (hostname === undefined) {
      result = connect_without_options();
    } else {
      if (typeof hostname === 'string') {
        opts = {
          hostname: hostname,
          port: port,
          username: username,
          password: password,
          privatekey: privatekey,
          passphrase: passphrase,
          totp: totp
        };
      } else {
        opts = hostname;
      }

      result = connect_with_options(opts);
    }

    if (result) {
      tab.state = CONNECTING;
      tab.title = result.title;
      tabManager.updateTabStatus(tab.id);
      if (hostname) {
        validated_form_data = result.data;
      }
      store_items(fields, result.data);
      store_default_command(result.data);
    }
  }

  wssh.connect = connect;

  $(form_id).submit(function(event){
    event.preventDefault();
    connect();
  });

  // Advanced options summary (shown when section is collapsed)
  function update_advanced_summary() {
    var summary = $('#advanced-summary');
    var section = $('#advanced-section');

    // Only show summary when section is collapsed
    if (section.is(':visible')) {
      summary.hide();
      return;
    }

    var tags = [];
    var command = $('#default-command').val();
    if (command && command.trim()) {
      tags.push('cmd: ' + command.trim());
    }
    if (user_key_enabled) {
      var key_source = $('input[name="key_source"]:checked').val();
      if (key_source === 'stored') {
        tags.push('using stored key');
      }
    }

    summary.empty();
    if (tags.length) {
      for (var i = 0; i < tags.length; i++) {
        summary.append($('<span>').addClass('summary-tag').text(tags[i]));
      }
      summary.show();
    } else {
      summary.hide();
    }
  }

  // Advanced options toggle
  $('#advanced-toggle').on('click', function(e) {
    e.preventDefault();
    e.stopPropagation();
    var section = $('#advanced-section');
    $(this).toggleClass('open');
    if (section.is(':visible')) {
      section.hide();
    } else {
      section.show();
    }
    update_advanced_summary();
  });

  // Auto-populate port and restore default command when hostname changes
  $('#hostname').on('change', function() {
    var port;
    if ($(this).is('select')) {
      port = $(this).find(':selected').data('port');
      if (port) {
        $('#port').val(port);
      }
    }
    restore_default_command($(this).val(), port || $('#port').val());
    update_advanced_summary();
  });

  // Restore default command when port changes
  $('#port').on('input change', function() {
    restore_default_command($('#hostname').val(), $(this).val());
    update_advanced_summary();
  });

  // Initialize port from dropdown on page load
  if ($('#hostname').is('select')) {
    $('#hostname').trigger('change');
  }

  // User key management toggle
  if (user_key_enabled) {
    $('input[name="key_source"]').on('change', function() {
      var val = $(this).val();
      if (val === 'stored') {
        $('#upload-key-row').hide();
        $('#stored-key-row').show();
      } else {
        $('#upload-key-row').show();
        $('#stored-key-row').hide();
      }
      update_advanced_summary();
    });

    $('#generate-key-btn').on('click', function() {
      var btn = $(this);

      if (has_stored_key) {
        if (!window.confirm('This will replace your existing SSH key pair. Continue?')) {
          return;
        }
      }

      btn.prop('disabled', true).text('Generating...');

      var xsrf = $('input[name="_xsrf"]').val();
      $.ajax({
        url: '/user-key',
        type: 'POST',
        data: {_xsrf: xsrf},
        dataType: 'json',
        success: function(resp) {
          if (resp.public_key) {
            $('#public-key-display').val(resp.public_key);
            has_stored_key = true;
            btn.text('Regenerate Key');
            $('#key_source_stored').prop('checked', true).trigger('change');
          }
        },
        error: function(xhr) {
          var msg = 'Failed to generate key';
          try {
            msg = JSON.parse(xhr.responseText).status || msg;
          } catch(e) {}
          window.alert(msg);
        },
        complete: function() {
          btn.prop('disabled', false);
        }
      });
    });
  }


  function cross_origin_connect(event)
  {
    console.log(event.origin);
    var prop = 'connect',
        args;

    try {
      args = JSON.parse(event.data);
    } catch (SyntaxError) {
      args = event.data.split('|');
    }

    if (!Array.isArray(args)) {
      args = [args];
    }

    // Create a new tab for cross-origin connections if current tab is connected
    var activeTab = tabManager.getActiveTab();
    if (activeTab && activeTab.state !== DISCONNECTED) {
      tabManager.createTab();
    }

    try {
      event_origin = event.origin;
      wssh[prop].apply(wssh, args);
    } finally {
      event_origin = undefined;
    }
  }

  window.addEventListener('message', cross_origin_connect, false);

  if (document.fonts) {
    document.fonts.ready.then(
      function () {
        if (custom_font_is_loaded() === false) {
          document.body.style.fontFamily = custom_font.family;
        }
      }
    );
  }


  // ===================== Window Resize (registered once) =====================

  $(window).resize(function(){
    var tab = tabManager.getActiveTab();
    if (tab && tab.term && tab.state === CONNECTED) {
      resize_terminal(tab.term);
    }
  });


  // ===================== New Tab Button =====================

  $('#new-tab-btn').on('click', function() {
    tabManager.createTab();
  });


  // ===================== Terminal Focus on Click =====================

  $('#terminals-container').on('click', function() {
    var tab = tabManager.getActiveTab();
    if (tab && tab.term && tab.state === CONNECTED) {
      tab.term.focus();
    }
  });


  // ===================== Tab Bar Click Refocus =====================

  $('#tab-bar').on('click', function(e) {
    var tab = tabManager.getActiveTab();
    if (tab && tab.term && tab.state === CONNECTED) {
      tab.term.focus();
    }
  });


  // ===================== Keyboard Shortcuts =====================

  $(document).on('keydown', function(e) {
    // Don't intercept when focused on form inputs
    var tag = e.target.tagName.toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select') {
      return;
    }

    if (e.altKey) {
      // Alt+T: New tab
      if (e.key === 't' || e.key === 'T') {
        e.preventDefault();
        tabManager.createTab();
        return;
      }

      // Alt+W: Close current tab
      if (e.key === 'w' || e.key === 'W') {
        e.preventDefault();
        if (tabManager.activeTabId !== null) {
          tabManager.closeTab(tabManager.activeTabId);
        }
        return;
      }

      // Alt+1-9: Switch to tab by number
      var num = parseInt(e.key, 10);
      if (num >= 1 && num <= 9) {
        e.preventDefault();
        var targetId = tabManager.getTabByIndex(num - 1);
        if (targetId !== null) {
          tabManager.activateTab(targetId);
        }
        return;
      }

      // Alt+Left: Previous tab
      if (e.key === 'ArrowLeft') {
        e.preventDefault();
        var ids = tabManager.getTabIds();
        var curIdx = ids.indexOf(tabManager.activeTabId);
        if (curIdx > 0) {
          tabManager.activateTab(ids[curIdx - 1]);
        }
        return;
      }

      // Alt+Right: Next tab
      if (e.key === 'ArrowRight') {
        e.preventDefault();
        var ids2 = tabManager.getTabIds();
        var curIdx2 = ids2.indexOf(tabManager.activeTabId);
        if (curIdx2 < ids2.length - 1) {
          tabManager.activateTab(ids2[curIdx2 + 1]);
        }
        return;
      }
    }
  });


  // ===================== Initialization =====================

  parse_url_data(
    decode_uri_component(window.location.search.substring(1)) + '&' + decode_uri_component(window.location.hash.substring(1)),
    url_safe_keys, opts_keys, url_form_data, url_opts_data
  );

  if (url_opts_data.term) {
    term_type.val(url_opts_data.term);
  }

  // Create the first tab
  tabManager.createTab();

  // Populate form
  if (get_object_length(url_form_data)) {
    populate_form(wrap_object(url_form_data));
  } else {
    restore_items(fields);
  }
  form_container.show();

  // Restore default command for the current hostname
  restore_default_command($('#hostname').val(), $('#port').val());

  // Update summary on default command field changes
  $('#default-command').on('input change', function() {
    update_advanced_summary();
  });

  // Initial summary update
  update_advanced_summary();

});
