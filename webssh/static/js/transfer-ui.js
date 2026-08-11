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
    return $('input[name="_xsrf"]').val() || '';
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
    var dir = get_cwd(tab_id) || '.';
    var dialog = $('#transfer-picker');
    var list = dialog.find('.picker-list').empty();
    var input = dialog.find('.picker-path').val(dir);

    $.getJSON('/transfer/list', {id: worker_id, path: dir})
      .done(function (data) {
        input.val(data.path);
        $.each(data.entries, function (i, entry) {
          var item = $('<div class="picker-item"></div>');
          item.toggleClass('is-dir', entry.is_dir);
          item.text(entry.name + (entry.is_dir ? '/' : ' \u2014 ' +
            webssh_transfer.format_bytes(entry.size)));
          if (!entry.is_dir) {
            // Directories are shown for orientation but are not selectable:
            // navigation is what would turn this into a file browser.
            item.on('click', function () {
              input.val(webssh_transfer.resolve_path(data.path, entry.name));
            });
          }
          list.append(item);
        });
        if (data.truncated) {
          list.append($('<div class="picker-note"></div>')
            .text('Listing truncated.'));
        }
      })
      .fail(function (xhr) {
        list.append($('<div class="picker-note"></div>')
          .text('Could not list directory (' + xhr.status + ')'));
      });

    dialog.addClass('visible');
    dialog.find('.picker-download').off('click').on('click', function () {
      var path = input.val();
      if (path) {
        window.location = webssh_transfer.download_url(worker_id, path);
      }
      dialog.removeClass('visible');
    });
    dialog.find('.picker-cancel').off('click').on('click', function () {
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
