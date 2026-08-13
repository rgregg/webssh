/*jslint browser:true */
/*
 * DOM wiring for file transfer: drop target, progress tray, download
 * picker. All decisions live in file-transfer.js; this file moves elements
 * and issues requests.
 */

var webssh_transfer_ui = (function () {
  'use strict';

  var cwd_by_tab = {};
  var active = {};
  var seq = 0;

  function xsrf() {
    // Reuses main.js's helper (exposed on the shared wssh object) rather
    // than duplicating the cookie-parsing logic here. tabManager.bindWssh
    // resets wssh on every tab activation/reconnect, but explicitly
    // preserves get_xsrf_token (alongside connect), so it is still
    // present here even after a session is connected.
    return window.wssh && window.wssh.get_xsrf_token ?
      window.wssh.get_xsrf_token() : '';
  }

  function set_cwd(tab_id, path) {
    cwd_by_tab[tab_id] = path;
  }

  function get_cwd(tab_id) {
    return cwd_by_tab[tab_id] || null;
  }

  function tray() {
    return $('#transfer-tray');
  }

  function add_row(label) {
    seq = seq + 1;
    var id = 'xfer-' + seq;
    var row = $('<div class="transfer-row" id="' + id + '"></div>');
    row.append($('<span class="transfer-label"></span>').text(label));
    row.append($('<span class="transfer-status">0%</span>'));
    row.append($('<button type="button" class="transfer-cancel">x</button>'));
    tray().append(row).addClass('visible');
    return row;
  }

  function finish_row(row, text) {
    row.find('.transfer-status').text(text);
    row.find('.transfer-cancel').remove();
    setTimeout(function () {
      row.fadeOut(400, function () {
        row.remove();
        if (!tray().children().length) {
          tray().removeClass('visible');
        }
      });
    }, 4000);
  }

  function track(tab_id, controller) {
    if (!active[tab_id]) {
      active[tab_id] = [];
    }
    active[tab_id].push(controller);
  }

  // Transfers are scoped to the session that owns them: closing the tab
  // aborts them rather than leaving a background transfer running against
  // a terminal the user believes is gone.
  function cancel_for_tab(tab_id) {
    var list = active[tab_id] || [];
    for (var i = 0; i < list.length; i++) {
      try {
        list[i].abort();
      } catch (e) {
        // Already settled; nothing to do.
      }
    }
    delete active[tab_id];
    delete cwd_by_tab[tab_id];
  }

  function send_upload(tab_id, worker_id, file, path, overwrite, row) {
    var controller = new AbortController();
    track(tab_id, controller);
    row.find('.transfer-cancel').off('click').on('click', function () {
      controller.abort();
    });

    fetch(webssh_transfer.upload_url(worker_id, path, file.name, overwrite), {
      method: 'POST',
      body: file,
      headers: {'X-Xsrftoken': xsrf()},
      signal: controller.signal
    }).then(function (response) {
      if (response.status === 409) {
        if (window.confirm(file.name + ' already exists. Overwrite?')) {
          send_upload(tab_id, worker_id, file, path, true, row);
          return null;
        }
        finish_row(row, 'cancelled');
        return null;
      }
      if (!response.ok) {
        return response.json().then(function (data) {
          finish_row(row, data.status || ('failed (' + response.status + ')'));
        }, function () {
          finish_row(row, 'failed (' + response.status + ')');
        });
      }
      return response.json().then(function (data) {
        finish_row(row, 'uploaded ' + webssh_transfer.format_bytes(data.bytes));
      });
    }).catch(function (err) {
      finish_row(row, err && err.name === 'AbortError' ? 'cancelled' : 'failed');
    });
  }

  function start_upload(tab_id, worker_id, file) {
    var dir = get_cwd(tab_id);
    var path;
    if (dir) {
      path = webssh_transfer.resolve_path(dir, file.name);
    } else {
      path = window.prompt('Upload ' + file.name + ' to:', '');
      if (!path) {
        return;
      }
    }
    var row = add_row('\u2191 ' + file.name);
    send_upload(tab_id, worker_id, file, path, false, row);
  }

  function open_picker(tab_id, worker_id) {
    var dialog = $('#transfer-picker');
    var list = dialog.find('.picker-list').empty();
    var input = dialog.find('.picker-path');

    // Everything the picker needs to remember for one open session.
    var state = {
      dir: null,          // directory currently listed
      entries: [],        // entries as returned by the server
      truncated: false,   // whether the server capped the listing
      seq: 0,             // request counter, for discarding stale responses
      timer: null         // pending re-list debounce
    };

    function note(text) {
      return $('<div class="picker-note"></div>').text(text);
    }

    function render(filter) {
      list.empty();
      var shown = 0;
      $.each(state.entries, function (i, entry) {
        if (!webssh_transfer.match_entry(entry.name, filter)) {
          return;
        }
        shown = shown + 1;
        var item = $('<div class="picker-item"></div>');
        item.toggleClass('is-dir', entry.is_dir);
        item.text(entry.name + (entry.is_dir ? '/' : ' \u2014 ' +
          webssh_transfer.format_bytes(entry.size)));
        item.on('click', function () {
          var path = webssh_transfer.resolve_path(state.dir, entry.name);
          // Clicking behaves exactly as typing the same text would, for
          // both kinds of row, so the list always reflects the box.
          input.val(entry.is_dir ? path + '/' : path);
          on_input();
        });
        list.append(item);
      });

      if (!shown) {
        list.append(note('No matching files'));
      }
      if (state.truncated) {
        // Filtering only searched what was fetched, so a missing file may
        // exist past the cap. Saying nothing would read as proof of absence.
        list.append(note(
          'Listing truncated at 1000 entries; the filter searched only those.'));
      }
    }

    function fetch_dir(dir) {
      state.seq = state.seq + 1;
      var mine = state.seq;
      $.getJSON('/transfer/list', {id: worker_id, path: dir})
        .done(function (data) {
          if (mine !== state.seq) {
            return;   // a newer request has been issued; this one is stale
          }
          state.dir = data.path;
          state.entries = data.entries;
          state.truncated = !!data.truncated;
          // The filter may have moved on while this was in flight.
          render(webssh_transfer.split_path(input.val()).filter);
        })
        .fail(function (xhr) {
          if (mine !== state.seq) {
            return;
          }
          // Keep the previous entries on screen: one mistyped character
          // should not cost the user their place.
          list.append(note('Could not list directory (' + xhr.status + ')'));
        });
    }

    function on_input() {
      var parts = webssh_transfer.split_path(input.val());
      if (parts.dir === null || parts.dir === state.dir) {
        render(parts.filter);   // local, instant, no request
        return;
      }
      if (state.timer) {
        clearTimeout(state.timer);
      }
      state.timer = setTimeout(function () {
        state.timer = null;
        fetch_dir(parts.dir);
      }, 250);
    }

    var start = get_cwd(tab_id) || '.';
    input.val(start);
    fetch_dir(start);

    // open_picker runs on every button press; without the off() the input
    // handlers stack, as the drop handlers once did.
    input.off('input.picker').on('input.picker', on_input);

    dialog.addClass('visible');
    dialog.find('.picker-download').off('click').on('click', function () {
      var path = input.val();
      if (path) {
        window.location = webssh_transfer.download_url(worker_id, path);
      }
      dialog.removeClass('visible');
    });
    dialog.find('.picker-cancel').off('click').on('click', function () {
      if (state.timer) {
        clearTimeout(state.timer);
      }
      dialog.removeClass('visible');
    });
  }

  function bind_drop(el, tab_id, worker_id) {
    var overlay = $('#transfer-drop-overlay');
    // bind_drop is called on every (re)connect for a tab, and the tab's
    // containerEl is reused across reconnects rather than recreated. Without
    // .off() first, each reconnect would stack another set of handlers on
    // the same element, so a single drop would fire start_upload once per
    // past connection. Rebinding fresh also means a drop always uses the
    // worker_id captured in *this* call, i.e. the current connection, not a
    // stale one from an earlier connect.
    el.off('dragover.transfer dragleave.transfer drop.transfer');
    el.on('dragover.transfer', function (e) {
      e.preventDefault();
      overlay.addClass('visible');
    });
    el.on('dragleave.transfer drop.transfer', function () {
      overlay.removeClass('visible');
    });
    el.on('drop.transfer', function (e) {
      e.preventDefault();
      var files = e.originalEvent.dataTransfer.files;
      for (var i = 0; i < files.length; i++) {
        start_upload(tab_id, worker_id, files[i]);
      }
    });
  }

  return {
    set_cwd: set_cwd,
    get_cwd: get_cwd,
    start_upload: start_upload,
    open_picker: open_picker,
    bind_drop: bind_drop,
    cancel_for_tab: cancel_for_tab
  };
}());
